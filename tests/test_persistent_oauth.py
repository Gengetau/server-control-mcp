"""Offline OAuth boundary tests using isolated private databases and loopback HTTP."""
import base64
from concurrent.futures import ThreadPoolExecutor
import hashlib
import http.client
import json
import os
from pathlib import Path
import secrets
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
import urllib.parse
import jwt
from server_control_mcp import persistent_oauth as p
from coding_tools_mcp import oauth
from coding_tools_mcp import server as upstream

ORIGIN = "https://mcp.example.test"
SECRET = b"test-only-signing-key-at-least-32-bytes!"
PASSWORD = "isolated-test-password"
p.install_persistence()

class Handler(p.PersistentOAuthMixin, upstream.MCPHandler):
    def log_message(self, *args):
        pass
    def handle_rpc(self, request, **kwargs):
        return {"jsonrpc":"2.0","id":request.get("id"),"result":{"ok":True}}

class OAuthTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name)/"state"/"oauth.sqlite3"
        self.cfg = self.config()
        self.server = None
    def config(self, password=PASSWORD):
        store = p.OAuthStore(self.path, ORIGIN, SECRET, password)
        return oauth.OAuthConfig(password, ORIGIN, SECRET, token_ttl=604800,
                                registry=p.PersistentRegistry(store),
                                pending_codes=p.PersistentCodes(store))
    def tearDown(self):
        self.stop()
        self.tmp.cleanup()
    def stop(self):
        if self.server:
            self.server.shutdown()
            self.server.server_close()
            self.thread.join(2)
            self.server = None
    def start(self):
        self.server = upstream.RuntimeHTTPServer(("127.0.0.1",0), Handler,
                         SimpleNamespace(oauth_config=self.cfg,close=lambda:None))
        self.port = self.server.server_port
        self.thread = threading.Thread(target=self.server.serve_forever,daemon=True)
        self.thread.start()
    def req(self, path, data=None, basic=None, token=None, raw=None):
        conn = http.client.HTTPConnection("127.0.0.1",self.port,timeout=3)
        headers = {}
        if path == "/oauth/register":
            body = json.dumps(data).encode()
            headers["Content-Type"] = "application/json"
        elif path == "/mcp":
            body = json.dumps({"jsonrpc":"2.0","id":1,"method":"initialize","params":{
                "protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}).encode()
            headers["Content-Type"] = "application/json"
            if token:headers["Authorization"]="Bearer "+token
        elif data is not None or raw is not None:
            body = raw if raw is not None else urllib.parse.urlencode(data).encode()
            headers["Content-Type"]="application/x-www-form-urlencoded"
        else:
            body = None
        if basic:
            encoded=base64.b64encode((basic[0]+":"+basic[1]).encode()).decode()
            headers["Authorization"]="Basic "+encoded
        conn.request("POST" if body is not None else "GET",path,body,headers)
        res=conn.getresponse()
        payload=res.read()
        result=json.loads(payload) if "json" in res.getheader("Content-Type","") else None
        reply=(res.status,res.headers,result,payload)
        conn.close()
        return reply
    def register(self, method="none"):
        result=self.cfg.registry.register({"redirect_uris":["http://127.0.0.1/callback"],
                "token_endpoint_auth_method":method,
                "grant_types":["authorization_code","refresh_token"]})
        return result
    def authorization(self, client):
        verifier=secrets.token_urlsafe(48)
        challenge=base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
        args={"client_id":client["client_id"],"redirect_uri":"http://127.0.0.1/callback",
              "code_challenge":challenge,"code_challenge_method":"S256","state":"test-state","resource":ORIGIN}
        status,headers,_,_=self.req("/oauth/authorize",{**args,"password":PASSWORD})
        self.assertEqual(status,302)
        location=urllib.parse.parse_qs(urllib.parse.urlsplit(headers["Location"]).query)
        self.assertEqual(location["state"],["test-state"])
        return {"grant_type":"authorization_code","client_id":client["client_id"],
                "code":location["code"][0],"redirect_uri":args["redirect_uri"],
                "code_verifier":verifier,"resource":ORIGIN}

    def test_registry_survives_reload_and_stores_only_secret_digest(self):
        client=self.register("client_secret_post")
        cfg=self.config()
        self.assertTrue(cfg.registry.authenticates(client["client_id"],client["client_secret"],"client_secret_post"))
        self.assertFalse(cfg.registry.authenticates(client["client_id"],"wrong","client_secret_post"))
        self.assertNotIn(client["client_secret"],json.dumps(cfg.registry.store.clients()))
        self.assertEqual(self.path.stat().st_mode & 0o777,0o600)
        self.assertEqual(self.path.parent.stat().st_mode & 0o777,0o700)

    def test_pending_authorization_code_survives_reload_and_is_atomic(self):
        code=secrets.token_urlsafe(32)
        self.cfg.pending_codes[code]={"expires_at":time.time()+300,"client_id":"fixture"}
        a,b=self.config().pending_codes,self.config().pending_codes
        with ThreadPoolExecutor(max_workers=2) as pool:
            values=list(pool.map(lambda mapping:mapping.pop(code,None),[a,b]))
        self.assertEqual(sum(v is not None for v in values),1)
        self.assertIsNone(self.config().pending_codes.pop(code,None))

    def test_refresh_binding_rotation_and_reuse_revoke(self):
        client=self.register()
        store=self.cfg.registry.store
        family,raw=store.issue(client["client_id"],ORIGIN)
        for cid,resource in [("other",ORIGIN),(client["client_id"],"https://other.example")]:
            with self.assertRaises(p.OAuthFault):store.rotate(raw,cid,resource)
        sid,resource,new=self.config().registry.store.rotate(raw,client["client_id"],None)
        self.assertEqual((sid,resource),(family,ORIGIN))
        self.assertNotEqual(raw,new)
        self.assertTrue(store.active(family,client["client_id"],ORIGIN))
        with self.assertRaises(p.OAuthFault):store.rotate(raw,client["client_id"],ORIGIN)
        self.assertFalse(store.active(family,client["client_id"],ORIGIN))
        with self.assertRaises(p.OAuthFault):store.rotate(new,client["client_id"],ORIGIN)

    def test_concurrent_refresh_one_winner_then_family_revocation(self):
        client=self.register()
        store=self.cfg.registry.store
        family,raw=store.issue(client["client_id"],ORIGIN)
        stores=[self.config().registry.store,self.config().registry.store]
        barrier=threading.Barrier(2)
        def rotate(s):
            barrier.wait()
            try:s.rotate(raw,client["client_id"]);return True
            except p.OAuthFault:return False
        with ThreadPoolExecutor(max_workers=2) as pool:
            results=list(pool.map(rotate,stores))
        self.assertEqual(results.count(True),1)
        self.assertFalse(store.active(family,client["client_id"],ORIGIN))

    def test_expired_refresh_is_rejected_without_renewal(self):
        client=self.register()
        store=self.cfg.registry.store
        _,raw=store.issue(client["client_id"],ORIGIN)
        with store.transaction() as db:
            db.execute("UPDATE refresh SET expires=?", (time.time()-1,))
        with self.assertRaises(p.OAuthFault):store.rotate(raw,client["client_id"])

    def test_refresh_values_never_stored_in_plaintext(self):
        client=self.register()
        store=self.cfg.registry.store
        _,raw=store.issue(client["client_id"],ORIGIN)
        with store.connection() as db:
            values=[r[0] for r in db.execute("SELECT digest FROM refresh")]
        self.assertEqual(values,[hashlib.sha256(raw.encode()).hexdigest()])
        self.assertNotIn(raw,repr(values))

    def test_signed_access_scope_audience_expiry_and_revoke(self):
        client=self.register()
        store=self.cfg.registry.store
        family,refresh=store.issue(client["client_id"],ORIGIN)
        response=p.token_response(self.cfg,ORIGIN,client["client_id"],family,refresh)
        token=response["access_token"]
        self.assertTrue(p.valid_access(token,self.config(),ORIGIN))
        claims=p.decode_access(token,self.cfg,ORIGIN)
        for key,value in [("exp",int(time.time())-1),("aud","https://other.example"),
                          ("scope","admin"),("sid","unknown"),("sub","other")]:
            edited={**claims,key:value}
            bad=jwt.encode(edited,SECRET,algorithm="HS256")
            self.assertFalse(p.valid_access(bad,self.cfg,ORIGIN))
        store.revoke(refresh,client["client_id"])
        self.assertFalse(p.valid_access(token,self.cfg,ORIGIN))

    def test_access_without_revocable_grant_is_rejected(self):
        now=int(time.time())
        claims={"iss":ORIGIN,"aud":ORIGIN,"sub":"preupgrade","client_id":"preupgrade",
                "iat":now-10,"exp":now+100,"scope":"mcp"}
        token=jwt.encode(claims,SECRET,algorithm="HS256")
        self.assertFalse(p.valid_access(token,self.cfg,ORIGIN))
        too_long=jwt.encode({**claims,"exp":claims["iat"]+604801},SECRET,algorithm="HS256")
        self.assertFalse(p.valid_access(too_long,self.cfg,ORIGIN))
        missing={**claims};missing.pop("iat")
        self.assertFalse(p.valid_access(jwt.encode(missing,SECRET,algorithm="HS256"),self.cfg,ORIGIN))

    def test_password_rotation_revokes_existing_grants(self):
        client=self.register()
        family,refresh=self.cfg.registry.store.issue(client["client_id"],ORIGIN)
        token=p.token_response(self.cfg,ORIGIN,client["client_id"],family,refresh)["access_token"]
        cfg=self.config(password="replacement-password")
        self.assertFalse(p.valid_access(token,cfg,ORIGIN))
        with self.assertRaises(p.OAuthFault):cfg.registry.store.rotate(refresh,client["client_id"])

    def test_origin_change_is_rejected(self):
        with self.assertRaises(RuntimeError):
            p.OAuthStore(self.path,"https://other.example",SECRET,PASSWORD)

    def test_http_discovery_and_dynamic_registration(self):
        self.start()
        status,_,metadata,_=self.req("/.well-known/oauth-authorization-server")
        self.assertEqual(status,200)
        self.assertIn("refresh_token",metadata["grant_types_supported"])
        self.assertEqual(metadata["revocation_endpoint"],ORIGIN+"/oauth/revoke")
        status,_,client,_=self.req("/oauth/register",{"redirect_uris":["http://127.0.0.1/callback"]})
        self.assertEqual(status,201)
        self.assertIn("refresh_token",client["grant_types"])

    def test_http_code_refresh_and_both_confidential_auth_methods(self):
        self.start()
        for method in ["none","client_secret_post","client_secret_basic"]:
            client=self.register(method)
            params=self.authorization(client)
            basic=None
            if method=="client_secret_post":params["client_secret"]=client["client_secret"]
            if method=="client_secret_basic":basic=(client["client_id"],client["client_secret"])
            status,_,tokens,_=self.req("/oauth/token",params,basic=basic)
            self.assertEqual(status,200)
            self.assertEqual(tokens["expires_in"],604800)
            self.assertEqual(tokens["refresh_token_expires_in"],90*86400)
            status,_,_,_=self.req("/mcp",token=tokens["access_token"])
            self.assertEqual(status,200)
            params={"grant_type":"refresh_token","client_id":client["client_id"],
                    "refresh_token":tokens["refresh_token"]}
            if method=="client_secret_post":params["client_secret"]=client["client_secret"]
            status,_,new,_=self.req("/oauth/token",params,basic=basic)
            self.assertEqual(status,200)
            self.assertNotEqual(new["refresh_token"],tokens["refresh_token"])

    def test_http_restart_keeps_pending_code_access_and_refresh(self):
        self.start()
        client=self.register()
        params=self.authorization(client)
        self.stop();self.cfg=self.config();self.start()
        status,_,tokens,_=self.req("/oauth/token",params)
        self.assertEqual(status,200)
        self.stop();self.cfg=self.config();self.start()
        self.assertEqual(self.req("/mcp",token=tokens["access_token"])[0],200)
        status,_,new,_=self.req("/oauth/token",{"grant_type":"refresh_token",
            "client_id":client["client_id"],"refresh_token":tokens["refresh_token"]})
        self.assertEqual(status,200)
        self.assertEqual(self.req("/mcp",token=new["access_token"])[0],200)
        self.assertEqual(self.req("/oauth/revoke",{"client_id":client["client_id"],
            "token":new["refresh_token"]})[0],200)
        self.assertEqual(self.req("/mcp",token=new["access_token"])[0],401)

    def test_http_pkce_duplicate_scope_and_cross_client_rejection(self):
        self.start()
        client=self.register()
        params=self.authorization(client)
        bad={**params,"code_verifier":secrets.token_urlsafe(48)}
        self.assertEqual(self.req("/oauth/token",bad)[0],400)
        self.assertEqual(self.req("/oauth/token",params)[0],400)
        status,_,body,_=self.req("/oauth/token",raw=b"client_id=a&client_id=b")
        self.assertEqual((status,body["error"]),(400,"invalid_request"))
        params=self.authorization(client)
        status,_,body,_=self.req("/oauth/token",{**params,"scope":"admin"})
        self.assertEqual((status,body["error"]),(400,"invalid_scope"))
        status,_,tokens,_=self.req("/oauth/token",params)
        self.assertEqual(status,200)
        other=self.register()
        status,_,body,_=self.req("/oauth/token",{"grant_type":"refresh_token",
            "client_id":other["client_id"],"refresh_token":tokens["refresh_token"]})
        self.assertEqual((status,body["error"]),(400,"invalid_grant"))
        self.assertEqual(self.req("/oauth/token",{"grant_type":"refresh_token",
            "client_id":client["client_id"],"refresh_token":tokens["refresh_token"]})[0],200)

if __name__ == "__main__":
    unittest.main(verbosity=2)

