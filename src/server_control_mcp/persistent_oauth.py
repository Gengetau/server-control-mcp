"""Persistent OAuth grants, extracted from the private server deployment.

Modified for public release: reject pre-upgrade access tokens without a grant.
"""
from __future__ import annotations
import base64
from collections.abc import MutableMapping
from contextlib import contextmanager
from dataclasses import asdict
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import sqlite3
import time
import urllib.parse
import jwt
from coding_tools_mcp import oauth
from coding_tools_mcp import server as upstream

REFRESH_TTL = 90 * 86400

class OAuthFault(Exception):
    def __init__(self, error, description):
        self.error, self.description = error, description

class OAuthStore:
    def __init__(self, path, origin, secret, password):
        self.path = Path(path)
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(self.path.parent, 0o700)
        self.origin = origin.rstrip("/")
        with self.connection() as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.executescript("""
                CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY,value TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS clients(id TEXT PRIMARY KEY,data TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS codes(code TEXT PRIMARY KEY,data TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS families(id TEXT PRIMARY KEY,client TEXT NOT NULL,
                    resource TEXT NOT NULL,revoked INTEGER NOT NULL DEFAULT 0);
                CREATE TABLE IF NOT EXISTS refresh(digest TEXT PRIMARY KEY,family TEXT NOT NULL,
                    expires REAL NOT NULL,used INTEGER NOT NULL DEFAULT 0);
                CREATE INDEX IF NOT EXISTS refresh_family ON refresh(family);
            """)
        os.chmod(self.path, 0o600)
        fingerprint = hmac.new(secret, (self.origin+"\0"+password).encode(), hashlib.sha256).hexdigest()
        with self.transaction() as db:
            previous = db.execute("SELECT value FROM meta WHERE key='origin'").fetchone()
            if previous and previous[0] != self.origin:
                raise RuntimeError("OAuth state belongs to another origin")
            db.execute("INSERT OR IGNORE INTO meta VALUES('origin',?)", (self.origin,))
            previous = db.execute("SELECT value FROM meta WHERE key='fingerprint'").fetchone()
            if previous and not secrets.compare_digest(previous[0], fingerprint):
                db.execute("UPDATE families SET revoked=1")
                db.execute("DELETE FROM codes")
            db.execute("INSERT OR REPLACE INTO meta VALUES('fingerprint',?)", (fingerprint,))

    @contextmanager
    def connection(self):
        db = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        db.row_factory = sqlite3.Row
        try:
            db.execute("PRAGMA synchronous=FULL")
            yield db
        finally:
            db.close()

    @contextmanager
    def transaction(self):
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                yield db
                db.execute("COMMIT")
            except BaseException:
                db.execute("ROLLBACK")
                raise

    def save_client(self, client):
        with self.transaction() as db:
            db.execute("INSERT OR REPLACE INTO clients VALUES(?,?)",
                       (client.client_id, json.dumps(asdict(client))))

    def clients(self):
        with self.connection() as db:
            return [json.loads(r[0]) for r in db.execute("SELECT data FROM clients")]

    def issue(self, client, resource):
        raw = "rt_" + secrets.token_urlsafe(48)
        family = secrets.token_urlsafe(24)
        with self.transaction() as db:
            db.execute("INSERT INTO families VALUES(?,?,?,0)", (family, client, resource))
            db.execute("INSERT INTO refresh VALUES(?,?,?,0)",
                       (self.digest(raw), family, time.time()+REFRESH_TTL))
        return family, raw

    @staticmethod
    def digest(raw):
        return hashlib.sha256(raw.encode()).hexdigest()

    def rotate(self, raw, client, resource=None):
        error = None
        new = "rt_" + secrets.token_urlsafe(48)
        with self.transaction() as db:
            row = db.execute("""SELECT r.*,f.client,f.resource,f.revoked FROM refresh r
                JOIN families f ON f.id=r.family WHERE r.digest=?""", (self.digest(raw),)).fetchone()
            if row is None or row["client"] != client:
                error = OAuthFault("invalid_grant", "Invalid refresh token")
            elif resource and resource != row["resource"]:
                error = OAuthFault("invalid_target", "Resource mismatch")
            elif row["revoked"] or row["expires"] <= time.time():
                error = OAuthFault("invalid_grant", "Refresh grant expired or revoked")
            elif row["used"]:
                db.execute("UPDATE families SET revoked=1 WHERE id=?", (row["family"],))
                error = OAuthFault("invalid_grant", "Refresh token reuse detected; grant revoked")
            else:
                db.execute("UPDATE refresh SET used=1 WHERE digest=?", (self.digest(raw),))
                db.execute("INSERT INTO refresh VALUES(?,?,?,0)",
                           (self.digest(new), row["family"], time.time()+REFRESH_TTL))
                family, bound_resource = row["family"], row["resource"]
        if error:
            raise error
        return family, bound_resource, new

    def active(self, family, client, resource):
        with self.connection() as db:
            row = db.execute("SELECT * FROM families WHERE id=?", (family,)).fetchone()
            return bool(row and not row["revoked"] and row["client"] == client and row["resource"] == resource)

    def revoke(self, token, client, family=None):
        with self.transaction() as db:
            if family is None:
                row = db.execute("SELECT family FROM refresh WHERE digest=?", (self.digest(token),)).fetchone()
                family = row[0] if row else None
            if family:
                db.execute("UPDATE families SET revoked=1 WHERE id=? AND client=?", (family, client))

class PersistentRegistry(oauth.OAuthClientRegistry):
    def __init__(self, store):
        super().__init__()
        self.store = store
        for value in store.clients():
            value["redirect_uris"] = tuple(value["redirect_uris"])
            client = oauth.OAuthClient(**value)
            self._clients[client.client_id] = client

    def register(self, metadata):
        result = super().register(metadata)
        client = self.get(result["client_id"])
        try:
            self.store.save_client(client)
        except BaseException:
            with self._lock:
                self._clients.pop(client.client_id, None)
            raise
        return result

    def add_preregistered(self, client_id, redirect_uris, *, client_secret):
        super().add_preregistered(client_id, redirect_uris, client_secret=client_secret)
        self.store.save_client(self.get(client_id))

class PersistentCodes(MutableMapping):
    def __init__(self, store):
        self.store = store
    def __iter__(self):
        with self.store.connection() as db:
            return iter([r[0] for r in db.execute("SELECT code FROM codes ORDER BY rowid")])
    def __len__(self):
        with self.store.connection() as db:
            return db.execute("SELECT COUNT(*) FROM codes").fetchone()[0]
    def __getitem__(self, code):
        with self.store.connection() as db:
            row = db.execute("SELECT data FROM codes WHERE code=?", (code,)).fetchone()
        if row is None:
            raise KeyError(code)
        return json.loads(row[0])
    def __setitem__(self, code, value):
        with self.store.transaction() as db:
            db.execute("INSERT OR REPLACE INTO codes VALUES(?,?)", (code, json.dumps(value)))
    def __delitem__(self, code):
        with self.store.transaction() as db:
            if not db.execute("DELETE FROM codes WHERE code=?", (code,)).rowcount:
                raise KeyError(code)
    def pop(self, code, default=None):
        with self.store.transaction() as db:
            row = db.execute("SELECT data FROM codes WHERE code=?", (code,)).fetchone()
            if row:
                db.execute("DELETE FROM codes WHERE code=?", (code,))
        return json.loads(row[0]) if row else default

def persistent_config(**kwargs):
    store = OAuthStore(os.environ.get("MCP_OAUTH_STATE_DB", "/state/oauth.sqlite3"),
                       kwargs["server_url"], kwargs["token_secret"], kwargs["password"])
    return oauth.OAuthConfig(**kwargs, registry=PersistentRegistry(store),
                             pending_codes=PersistentCodes(store))

def install_persistence():
    os.umask(0o077)
    upstream.OAuthConfig = persistent_config
    oauth.OAUTH_GRANT_TYPES_SUPPORTED = ("authorization_code", "refresh_token")
    upstream.OAUTH_GRANT_TYPES_SUPPORTED = oauth.OAUTH_GRANT_TYPES_SUPPORTED

def decode_access(token, cfg, origin, *, verify_exp=True):
    return jwt.decode(token, cfg.token_secret, algorithms=["HS256"], audience=origin,
                      issuer=origin, options={"verify_exp":verify_exp,
                      "require":["iss","aud","sub","client_id","iat","exp","scope"]})

def valid_access(token, cfg, origin):
    try:
        claims = decode_access(token, cfg, origin)
        client = claims["client_id"]
        if not isinstance(client, str) or claims["sub"] != client or claims["scope"] != "mcp":
            return False
        sid = claims.get("sid")
        store = cfg.registry.store
        if sid is not None:
            return isinstance(sid, str) and cfg.registry.get(client) is not None and store.active(sid, client, origin)
        return False  # Every access token requires a revocable grant.
    except (jwt.PyJWTError, ValueError, KeyError, TypeError, sqlite3.Error):
        return False

def token_response(cfg, origin, client, family, refresh):
    now = int(time.time())
    access = jwt.encode({"iss":origin,"aud":origin,"sub":client,"client_id":client,
                         "iat":now,"exp":now+cfg.token_ttl,"scope":"mcp","sid":family},
                        cfg.token_secret, algorithm="HS256")
    return {"access_token":access,"token_type":"Bearer","expires_in":cfg.token_ttl,
            "refresh_token":refresh,"refresh_token_expires_in":REFRESH_TTL,"scope":"mcp"}

class PersistentOAuthMixin:
    def is_authorized(self):
        cfg = self.runtime.oauth_config
        header = self.headers.get("Authorization", "").strip()
        return bool(cfg and header.startswith("Bearer ") and valid_access(header[7:], cfg, self.oauth_base_url()))

    def handle_oauth_as_metadata(self, *, head_only=False):
        base = self.oauth_base_url()
        self.send_json({"issuer":base,"authorization_endpoint":base+"/oauth/authorize",
                        "token_endpoint":base+"/oauth/token","registration_endpoint":base+"/oauth/register",
                        "revocation_endpoint":base+"/oauth/revoke",
                        "response_types_supported":["code"],
                        "grant_types_supported":["authorization_code","refresh_token"],
                        "code_challenge_methods_supported":["S256"],
                        "scopes_supported":["mcp"],
                        "token_endpoint_auth_methods_supported":list(upstream.OAUTH_TOKEN_AUTH_METHODS),
                        "revocation_endpoint_auth_methods_supported":list(upstream.OAUTH_TOKEN_AUTH_METHODS)},
                       head_only=head_only)

    def _token_params(self):
        body = self._read_oauth_body()
        if body is None:
            return None
        if self.headers.get_content_type().lower() != "application/x-www-form-urlencoded":
            raise OAuthFault("invalid_request", "Form content type required")
        try:
            fields = urllib.parse.parse_qs(body.decode("utf-8"), keep_blank_values=True, max_num_fields=32)
        except (UnicodeError, ValueError):
            raise OAuthFault("invalid_request", "Invalid form body")
        if any(len(v) != 1 for v in fields.values()):
            raise OAuthFault("invalid_request", "Duplicate parameters")
        return {k:v[0] for k,v in fields.items()}

    def _client(self, params):
        cid, secret = params.get("client_id", ""), params.get("client_secret", "")
        method = "client_secret_post" if secret else "none"
        header = self.headers.get("Authorization", "")
        if header:
            if not header.startswith("Basic ") or "client_secret" in params:
                raise OAuthFault("invalid_client", "Ambiguous client authentication")
            try:
                decoded = base64.b64decode(header[6:], validate=True).decode("utf-8")
                basic_id, separator, basic_secret = decoded.partition(":")
                if not separator:
                    raise ValueError("missing separator")
                basic_id, basic_secret = urllib.parse.unquote(basic_id), urllib.parse.unquote(basic_secret)
                if cid and cid != basic_id:
                    raise ValueError("client mismatch")
                cid, secret, method = basic_id, basic_secret, "client_secret_basic"
            except (ValueError, UnicodeError):
                raise OAuthFault("invalid_client", "Invalid client authentication")
        if not self.runtime.oauth_config.registry.authenticates(cid, secret, method):
            raise OAuthFault("invalid_client", "Invalid client authentication")
        return cid

    def handle_oauth_token(self):
        try:
            params = self._token_params()
            if params is None:
                return
            cfg = self.runtime.oauth_config
            client = self._client(params)
            origin = self.oauth_base_url()
            resource = params.get("resource", "").rstrip("/")
            scope = params.get("scope")
            if scope is not None and scope != "mcp":
                raise OAuthFault("invalid_scope", "Only the consented mcp scope is supported")
            grant = params.get("grant_type")
            if grant == "refresh_token":
                raw = params.get("refresh_token", "")
                if not raw:
                    raise OAuthFault("invalid_grant", "Refresh token is required")
                family, resource, raw = cfg.registry.store.rotate(raw, client, resource or None)
            elif grant == "authorization_code":
                verifier = params.get("code_verifier", "")
                if not re.fullmatch(r"[A-Za-z0-9\-._~]{43,128}", verifier):
                    raise OAuthFault("invalid_grant", "Invalid code verifier")
                with cfg.pending_codes_lock:
                    code = cfg.pending_codes.pop(params.get("code", ""), None)
                if not code or code["expires_at"] <= time.time():
                    raise OAuthFault("invalid_grant", "Authorization code expired or already used")
                if code["client_id"] != client or code["redirect_uri"] != params.get("redirect_uri"):
                    raise OAuthFault("invalid_grant", "Authorization code binding mismatch")
                if resource != origin or code.get("resource") != origin or code.get("server_url") != origin:
                    raise OAuthFault("invalid_target", "Resource mismatch")
                if not oauth.verify_pkce(verifier, code["code_challenge"]):
                    raise OAuthFault("invalid_grant", "PKCE verification failed")
                family, raw = cfg.registry.store.issue(client, resource)
            else:
                raise OAuthFault("unsupported_grant_type", "Unsupported grant type")
            self.send_json(token_response(cfg, origin, client, family, raw))
        except OAuthFault as error:
            self.send_json({"error":error.error,"error_description":error.description}, status=400)
        except sqlite3.Error:
            self.send_json({"error":"temporarily_unavailable"}, status=503)

    def do_POST(self):
        if urllib.parse.urlsplit(self.path).path != "/oauth/revoke":
            return super().do_POST()
        try:
            params = self._token_params()
            if params is None:
                return
            client = self._client(params)
            raw = params.get("token", "")
            cfg = self.runtime.oauth_config
            family = None
            if not raw.startswith("rt_") and raw:
                try:
                    claims = decode_access(raw, cfg, self.oauth_base_url(), verify_exp=False)
                    if claims.get("client_id") == client:
                        family = claims.get("sid")
                except jwt.PyJWTError:
                    pass
            cfg.registry.store.revoke(raw, client, family)
            self.send_json({})
        except OAuthFault as error:
            self.send_json({"error":error.error,"error_description":error.description}, status=400)
        except sqlite3.Error:
            self.send_json({"error":"temporarily_unavailable"}, status=503)

