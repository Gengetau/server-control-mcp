"""Persistent OAuth grants, extracted from the private server deployment.

Modified for public release: reject pre-upgrade access tokens without a grant.
"""
from __future__ import annotations
import base64
from collections.abc import MutableMapping
from contextlib import contextmanager
from dataclasses import asdict
import fnmatch
import hashlib
import hmac
import io
import json
import os
from pathlib import Path
import posixpath
import re
import secrets
import sqlite3
import time
import urllib.parse
import jwt
from coding_tools_mcp import oauth
from coding_tools_mcp import server as upstream

REFRESH_TTL = 90 * 86400
PRM_PATH = "/.well-known/oauth-protected-resource"
LEGACY_MCP_HEADER_ALIASES = frozenset({"2025-03-26", "2024-11-05"})
OAUTH_POST_PATHS = frozenset({"/oauth/authorize", "/oauth/token", "/oauth/register", "/oauth/revoke"})
# Google account linking (Gemini Connected Apps) does not always persist a
# rotated refresh token. Only clients whose redirect URIs are all Google's
# HTTPS OAuth redirect hosts get lost-rotation recovery (see OAuthStore.rotate).
GOOGLE_REDIRECT_PATTERNS = ("oauth-redirect.googleusercontent.com",
                            "oauth-redirect-*.googleusercontent.com")

class ChunkedEncodingError(Exception):
    pass

class ChunkedBodyTooLarge(Exception):
    def __init__(self, max_bytes: int):
        self.max_bytes = max_bytes

def read_chunked_body(rfile, max_bytes: int) -> bytes:
    """Decode an HTTP/1.1 chunked request body (RFC 9112 section 7.1) with strict bounds."""
    out = bytearray()
    while True:
        line = rfile.readline(4098)
        if not line or len(line) > 4096 or not line.endswith(b"\r\n"):
            raise ChunkedEncodingError("Malformed chunk size line")
        size_part = line[:-2].split(b";", 1)[0].strip()
        if not size_part or not re.fullmatch(rb"[0-9A-Fa-f]{1,8}", size_part):
            raise ChunkedEncodingError("Invalid chunk size")
        chunk_size = int(size_part, 16)
        if chunk_size == 0:
            for _ in range(64):
                trailer = rfile.readline(4098)
                if not trailer or len(trailer) > 4096 or not trailer.endswith(b"\r\n"):
                    raise ChunkedEncodingError("Malformed chunk trailer")
                if trailer == b"\r\n":
                    return bytes(out)
            raise ChunkedEncodingError("Too many chunk trailer lines")
        if len(out) + chunk_size > max_bytes:
            raise ChunkedBodyTooLarge(max_bytes)
        chunk = rfile.read(chunk_size)
        if len(chunk) != chunk_size:
            raise ChunkedEncodingError("Truncated chunk payload")
        if rfile.read(2) != b"\r\n":
            raise ChunkedEncodingError("Missing chunk CRLF terminator")
        out.extend(chunk)

def canonical_resource(value, origin):
    """RFC 8707 resource is optional; this gateway protects one MCP resource.
    Accept omitted, the origin, or origin + /mcp; anything else is rejected."""
    norm = (value or "").rstrip("/")
    if norm in ("", origin, origin + upstream.MCP_ENDPOINT_PATH):
        return origin
    return None

def _google_redirect_uri(uri: str) -> bool:
    try:
        parts = urllib.parse.urlsplit(uri)
        host = (parts.hostname or "").lower()
        port = parts.port
    except ValueError:
        return False
    if parts.scheme != "https" or port not in (None, 443) or not host:
        return False
    return any(
        fnmatch.fnmatchcase(host, pat) and host.count(".") == pat.count(".")
        for pat in GOOGLE_REDIRECT_PATTERNS
    )

def google_redirect_client(registry, client_id) -> bool:
    client = registry.get(client_id)
    uris = tuple(getattr(client, "redirect_uris", ()) or ())
    return bool(uris) and all(isinstance(u, str) and _google_redirect_uri(u) for u in uris)

def client_authenticates(registry, client_id, secret, method):
    if registry.authenticates(client_id, secret, method):
        return True
    # Confidential clients may present their secret by post or basic,
    # whichever they registered (RFC 6749 2.3.1); public clients stay strict.
    confidential = {"client_secret_post", "client_secret_basic"}
    client = registry.get(client_id)
    return bool(client and secret and method in confidential
                and client.token_endpoint_auth_method in confidential
                and client.verifies_secret(secret))

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

    def rotate(self, raw, client, resource=None, *, allow_lost_rotation=False):
        error = None
        new = "rt_" + secrets.token_urlsafe(48)
        with self.transaction() as db:
            row = db.execute("""SELECT r.rowid AS rid,r.*,f.client,f.resource,f.revoked FROM refresh r
                JOIN families f ON f.id=r.family WHERE r.digest=?""", (self.digest(raw),)).fetchone()
            if row is None or row["client"] != client:
                error = OAuthFault("invalid_grant", "Invalid refresh token")
            elif resource and resource != row["resource"]:
                error = OAuthFault("invalid_target", "Resource mismatch")
            elif row["revoked"] or row["expires"] <= time.time():
                error = OAuthFault("invalid_grant", "Refresh grant expired or revoked")
            elif row["used"] and not (allow_lost_rotation and not db.execute(
                    "SELECT 1 FROM refresh WHERE family=? AND rowid>? AND used=1 LIMIT 1",
                    (row["family"], row["rid"])).fetchone()):
                db.execute("UPDATE families SET revoked=1 WHERE id=?", (row["family"],))
                error = OAuthFault("invalid_grant", "Refresh token reuse detected; grant revoked")
            else:
                if row["used"]:
                    # Lost rotation: no newer token of this family was ever
                    # presented, so the client never received it. Retire
                    # those unseen successors and continue the family.
                    db.execute("UPDATE refresh SET used=1 WHERE family=? AND rowid>?",
                               (row["family"], row["rid"]))
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

    # RFC 9728 path-aware protected resource metadata. Clients such as Gemini
    # custom apps compare the metadata "resource" with the configured MCP URL
    # (origin + /mcp). Both metadata URLs describe the /mcp endpoint; tokens
    # stay bound to the origin internally (canonical_resource).
    def mcp_resource_url(self):
        return self.oauth_base_url() + upstream.MCP_ENDPOINT_PATH

    def handle_oauth_resource_metadata(self, *, head_only=False):
        if self.runtime.oauth_config is None:
            return super().handle_oauth_resource_metadata(head_only=head_only)
        self.send_json({"resource":self.mcp_resource_url(),
                        "authorization_servers":[self.oauth_base_url()],
                        "bearer_methods_supported":["header"],
                        "scopes_supported":["mcp"]}, head_only=head_only)

    def handle_metadata_request(self, *, head_only):
        normalized = posixpath.normpath(self.path.split("?", 1)[0])
        if normalized == PRM_PATH + upstream.MCP_ENDPOINT_PATH:
            return self.handle_oauth_resource_metadata(head_only=head_only)
        return super().handle_metadata_request(head_only=head_only)

    def do_OPTIONS(self):
        normalized = posixpath.normpath(self.path.split("?", 1)[0])
        if normalized in {PRM_PATH + upstream.MCP_ENDPOINT_PATH, "/oauth/revoke"}:
            origin = self.headers.get("Origin")
            if origin and not upstream.is_allowed_origin(origin):
                return self.send_json({"error": "Origin denied"}, status=403)
            self.send_response(204)
            self.send_header("Allow", "GET, HEAD, POST, OPTIONS")
            self.send_cors_headers()
            self.end_headers()
            return
        return super().do_OPTIONS()

    def send_unauthorized(self, *, head_only=False):
        if self.runtime.oauth_config is None:
            return super().send_unauthorized(head_only=head_only)
        base = self.oauth_base_url()
        www_auth = (f'Bearer realm="coding-tools-mcp", resource_metadata='
                    f'"{base}{PRM_PATH}{upstream.MCP_ENDPOINT_PATH}", scope="mcp"')
        self.send_rpc_error(-32000, "Unauthorized", status=401,
                            extra_headers={"WWW-Authenticate": www_auth}, head_only=head_only)

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
        if not client_authenticates(self.runtime.oauth_config.registry, cid, secret, method):
            raise OAuthFault("invalid_client", "Invalid client authentication")
        return cid

    def _canonical_resource_pairs(self, pairs):
        """Rewrite the first resource value (the one upstream reads) to the
        canonical origin when it names this server or is omitted."""
        origin, out, seen = self.oauth_base_url(), [], False
        for key, value in pairs:
            if key == "resource" and not seen:
                seen = True
                value = canonical_resource(value, origin) or value
            out.append((key, value))
        if not seen:
            out.append(("resource", origin))
        return out

    def handle_oauth_authorize_get(self):
        if self.runtime.oauth_config is not None:
            parts = urllib.parse.urlsplit(self.path)
            try:
                pairs = urllib.parse.parse_qsl(parts.query, keep_blank_values=True, max_num_fields=64)
                self.path = urllib.parse.urlunsplit(("", "", parts.path,
                    urllib.parse.urlencode(self._canonical_resource_pairs(pairs)), ""))
            except ValueError:
                pass
        return super().handle_oauth_authorize_get()

    def handle_oauth_authorize_post(self):
        if self.runtime.oauth_config is None:
            return super().handle_oauth_authorize_post()
        body = self._read_oauth_body()
        if body is None:
            return None
        if self.headers.get_content_type().lower() == "application/x-www-form-urlencoded":
            try:
                pairs = urllib.parse.parse_qsl(body.decode("utf-8"), keep_blank_values=True, max_num_fields=64)
                body = urllib.parse.urlencode(self._canonical_resource_pairs(pairs)).encode()
            except (UnicodeError, ValueError):
                pass
        original = self.rfile
        self.rfile = io.BytesIO(body)
        self.headers.replace_header("Content-Length", str(len(body)))
        try:
            return super().handle_oauth_authorize_post()
        finally:
            self.rfile = original

    def handle_oauth_token(self):
        try:
            params = self._token_params()
            if params is None:
                return
            cfg = self.runtime.oauth_config
            client = self._client(params)
            origin = self.oauth_base_url()
            presented = params.get("resource", "")
            resource = canonical_resource(presented, origin)
            if resource is None:
                raise OAuthFault("invalid_target", "Resource mismatch")
            scope = params.get("scope")
            if scope is not None and scope != "mcp":
                raise OAuthFault("invalid_scope", "Only the consented mcp scope is supported")
            grant = params.get("grant_type")
            if grant == "refresh_token":
                raw = params.get("refresh_token", "")
                if not raw:
                    raise OAuthFault("invalid_grant", "Refresh token is required")
                family, resource, raw = cfg.registry.store.rotate(
                    raw, client, resource if presented else None,
                    allow_lost_rotation=google_redirect_client(cfg.registry, client))
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

    def _dispatch_post_inner(self, normalized: str):
        if normalized == "/oauth/revoke":
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
            return
        return super().do_POST()

    def do_POST(self):
        normalized = posixpath.normpath(self.path.split("?", 1)[0])
        is_mcp = normalized == upstream.MCP_ENDPOINT_PATH
        if is_mcp:
            versions = self.headers.get_all("MCP-Protocol-Version") or []
            if len(versions) == 1 and versions[0].strip() in LEGACY_MCP_HEADER_ALIASES:
                self.headers.replace_header("MCP-Protocol-Version", "2025-06-18")

        te_values = self.headers.get_all("Transfer-Encoding")
        if not te_values:
            return self._dispatch_post_inner(normalized)

        is_oauth = normalized in OAUTH_POST_PATHS
        def reject(status: int, message: str, *, data=None):
            self.close_connection = True
            if is_mcp:
                self.send_rpc_error(-32600, message, status=status, data=data)
            else:
                self.send_json({"error": "invalid_request", "error_description": message}, status=status)

        if self.headers.get("Content-Length") is not None:
            return reject(400, "Conflicting Transfer-Encoding and Content-Length")
        codings = [t.strip().lower() for v in te_values for t in v.split(",") if t.strip()]
        if codings != ["chunked"]:
            return reject(501, "Unsupported Transfer-Encoding")
        if not is_mcp and not is_oauth:
            self.close_connection = True
            return self.send_rpc_error(-32601, "Unknown endpoint", status=404)
        if is_mcp:
            origin = self.headers.get("Origin")
            if origin and not upstream.is_allowed_origin(origin):
                self.close_connection = True
                return self.send_rpc_error(-32600, "Origin denied", status=403)
            if not self.is_authorized():
                self.close_connection = True
                return self.send_unauthorized()
            if self.headers.get_content_type().lower() != "application/json":
                self.close_connection = True
                return self.send_rpc_error(-32600, "Content-Type must be application/json", status=415)

        max_bytes = upstream.MAX_HTTP_REQUEST_BYTES if is_mcp else oauth.OAUTH_MAX_BODY_BYTES
        try:
            body = read_chunked_body(self.rfile, max_bytes)
        except ChunkedBodyTooLarge:
            return reject(413, "Request body exceeds maximum size", data={"max_bytes": max_bytes})
        except ChunkedEncodingError as exc:
            return reject(400, str(exc))

        del self.headers["Transfer-Encoding"]
        del self.headers["Content-Length"]
        self.headers["Content-Length"] = str(len(body))
        original = self.rfile
        self.rfile = io.BytesIO(body)
        try:
            return self._dispatch_post_inner(normalized)
        finally:
            self.rfile = original
