"""Authenticated HTTP facade subscription and client isolation regression."""
import base64,http.client,json
from pathlib import Path
import tempfile,threading,unittest
from types import SimpleNamespace
from unittest.mock import patch
from coding_tools_mcp import oauth,server,protocol
from server_control_mcp import persistent_oauth as p
from server_control_mcp.events import Events,EventFeed
from server_control_mcp.gateway import GatewayHandler

class GatewayEventsTests(unittest.TestCase):
    def test_authenticated_principal_drives_subscription_and_delivery(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);origin='https://mcp.example.test'
            store=p.OAuthStore(root/'oauth.sqlite3',origin,b'test-only-signing-key-at-least-32-bytes!','password')
            cfg=oauth.OAuthConfig('password',origin,b'test-only-signing-key-at-least-32-bytes!',
                registry=p.PersistentRegistry(store),pending_codes=p.PersistentCodes(store))
            feed=EventFeed(root/'outbox.sqlite3');sent=[]
            def send(url,key,sid,eid,payload):
                sent.append(payload)
                return (200,json.dumps({'challenge':payload['challenge']}).encode()) if payload.get('type')=='verification' else (204,b'')
            events=Events(root/'events.sqlite3',read_feed=feed,send=send)
            runtime=SimpleNamespace(oauth_config=cfg,scm_events=events,close=lambda:None,
                                    server_identity=lambda:{'name':'test','version':'1'})
            http=server.RuntimeHTTPServer(('127.0.0.1',0),GatewayHandler,runtime)
            thread=threading.Thread(target=http.serve_forever,daemon=True);thread.start()
            def client():
                c=cfg.registry.register({'redirect_uris':['http://127.0.0.1/callback']})['client_id']
                family,refresh=store.issue(c,origin)
                return c,family,p.token_response(cfg,origin,c,family,refresh)['access_token']
            a,af,at=client();b,bf,bt=client()
            args={'name':'server.changed','arguments':{},'delivery':{'mode':'webhook',
                'url':'https://callback.example/events','secret':'whsec_'+base64.b64encode(b'x'*32).decode()}}
            def request(method,token,params=args):
                body={'jsonrpc':'2.0','id':1,'method':method,'params':{**params,'_meta':{
                    protocol.META_PROTOCOL_VERSION:'2026-07-28',protocol.META_CLIENT_CAPABILITIES:{}}}}
                headers={'Content-Type':'application/json','MCP-Protocol-Version':'2026-07-28','Mcp-Method':method}
                if 'name' in params:headers['Mcp-Name']=params['name']
                if token:headers['Authorization']='Bearer '+token
                conn=httpclient_module.HTTPConnection('127.0.0.1',http.server_port,timeout=3)
                try:
                    conn.request('POST','/mcp',json.dumps(body),headers);r=conn.getresponse()
                    return r.status,json.loads(r.read())
                finally:conn.close()
            # Keep the HTTP module separate from the server variable above.
            import http.client as httpclient_module
            try:
                self.assertEqual(request('events/subscribe',None)[0],401)
                with patch('server_control_mcp.events.destination',return_value=(None,None)):
                    status,result=request('events/subscribe',at)
                self.assertEqual(status,200);self.assertIn('id',result['result'])
                request('events/unsubscribe',bt)
                with events.db() as db:
                    row=db.execute('select owner,family from subscriptions').fetchone()
                self.assertEqual(row,(a,af))
                feed.emit('task.other',b);event_id=feed.emit('task.assigned',a)
                events.tick(store.active)
                notifications=[x for x in sent if 'eventId' in x]
                self.assertEqual(len(notifications),1)
                self.assertEqual(notifications[0]['data']['id'],event_id)
                store.revoke('',a,af);events.tick(store.active)
                self.assertEqual(request('events/list',at,{})[0],401)
                with events.db() as db:self.assertEqual(db.execute('select count(*) from subscriptions').fetchone()[0],0)
            finally:http.shutdown();http.server_close();thread.join(2)

    def test_events_rpc_rechecks_revoked_and_malformed_tokens(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);origin='https://mcp.example.test'
            store=p.OAuthStore(root/'oauth.sqlite3',origin,b'test-only-signing-key-at-least-32-bytes!','password')
            cfg=oauth.OAuthConfig('password',origin,b'test-only-signing-key-at-least-32-bytes!',
                registry=p.PersistentRegistry(store),pending_codes=p.PersistentCodes(store))
            events=Events(root/'events.sqlite3',read_feed=EventFeed(root/'outbox.sqlite3'),send=lambda *a:(204,b''))
            runtime=SimpleNamespace(oauth_config=cfg,scm_events=events,
                                    server_identity=lambda:{'name':'test','version':'1'})
            c=cfg.registry.register({'redirect_uris':['http://127.0.0.1/callback']})['client_id']
            family,refresh=store.issue(c,origin)
            token=p.token_response(cfg,origin,c,family,refresh)['access_token']
            def call(auth):
                h=GatewayHandler.__new__(GatewayHandler)
                h.server=SimpleNamespace(runtime=runtime);h.headers={'Authorization':auth} if auth is not None else {}
                h.oauth_base_url=lambda:origin
                req={'jsonrpc':'2.0','id':1,'method':'events/list','params':{'_meta':{
                    protocol.META_PROTOCOL_VERSION:'2026-07-28',protocol.META_CLIENT_CAPABILITIES:{}}}}
                return h.handle_rpc(req)
            self.assertIn('result',call('Bearer '+token))
            for auth in (None,'Basic '+token,'xxxxxxx'+token,'Bearer '):
                self.assertEqual(call(auth)['error']['code'],-32001)
            store.revoke('',c,family)
            self.assertEqual(call('Bearer '+token)['error']['code'],-32001)
if __name__=='__main__':unittest.main()
