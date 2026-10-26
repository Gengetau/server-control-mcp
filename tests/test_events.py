import base64
import hashlib
import hmac
import json
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch
from server_control_mcp import events as m

class EventsTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.items = []
        self.sent = []
        self.status = 204
        self.path = Path(self.tmp.name)/'events.sqlite3'
        self.adapter = m.Events(self.path, self.feed, self.send)
        self.principal = ('owner', 'family', 'https://mcp.example')
        self.params = {'name': m.EVENT, 'arguments': {}, 'delivery': {'mode':'webhook',
            'url':'https://callback.example/receive',
            'secret':'whsec_'+base64.b64encode(b'isolated-test-key-32-bytes-exact!!').decode()}}
        self.dest = patch.object(m, 'destination', return_value=(None,None))
        self.dest.start()
        self.addCleanup(self.dest.stop)
        self.addCleanup(self.tmp.cleanup)

    def feed(self, after):
        items = [i for i in self.items if i['id'] > after][:50]
        return {'events':items, 'next_after':items[-1]['id'] if items else after}

    def send(self,url,key,sid,eid,payload):
        self.sent.append((sid,eid,payload))
        if payload.get('type') == 'verification':
            return 200,json.dumps({'challenge':payload['challenge']}).encode()
        return self.status,b''

    def subscribe(self):
        return self.adapter.call('events/subscribe', self.params, self.principal)

    def item(self, i):
        return {'id':i,'kind':'task.updated','at':'2026-10-21T06:00:00+00:00',
                'summary':'private text must never be sent','by':'private','ref':'private',
                'recipient':'owner'}

    def test_unrelated_batches_advance_without_delivery(self):
        self.subscribe(); n=len(self.sent)
        self.items=[{**self.item(i),'recipient':'other'} for i in range(1,102)]
        for _ in range(3):self.adapter.tick(lambda *a:True)
        self.assertEqual(len(self.sent),n)
        with self.adapter.db() as c:self.assertEqual(c.execute('select cursor from subscriptions').fetchone()[0],101)
        self.items.append(self.item(102)); self.adapter.tick(lambda *a:True)
        self.assertEqual(self.sent[-1][2]['data']['id'],102)

    def test_filter_checkpoint_does_not_skip_failed_directed_event(self):
        self.subscribe(); self.status=503
        self.items=[{**self.item(1),'recipient':'other'},self.item(2),
                    {**self.item(3),'recipient':'other'}]
        self.adapter.tick(lambda *a:True)
        with self.adapter.db() as c:self.assertEqual(c.execute('select cursor from subscriptions').fetchone()[0],1)

    def test_catalog(self):
        self.assertEqual(self.adapter.call('events/list',{},self.principal),m.CATALOG)

    def test_idempotent_persistent_subscription(self):
        one=self.subscribe(); two=self.subscribe()
        self.assertEqual(one['id'],two['id'])
        with m.Events(self.path).db() as c:
            self.assertEqual(c.execute('select count(*) from subscriptions').fetchone()[0],1)
        self.assertEqual(self.path.stat().st_mode & 0o777,0o600)

    def test_baseline_no_history_and_minimal_delivery(self):
        self.items=[self.item(1)]; self.subscribe()
        self.items.append(self.item(2)); self.adapter.tick(lambda *a:True)
        payload=self.sent[-1][2]
        self.assertEqual(payload['data'],{'id':2,'kind':'task.updated','at':'2026-10-21T06:00:00+00:00'})
        self.assertNotIn('private',json.dumps(payload))
        self.assertEqual(payload['timestamp'],'2026-10-21T06:00:00+00:00')
        n=len(self.sent); self.adapter.tick(lambda *a:True)
        self.assertEqual(n,len(self.sent))

    def test_retry_id_and_cursor(self):
        self.subscribe(); self.items=[self.item(1)]; self.status=503
        self.adapter.tick(lambda *a:True); eid=self.sent[-1][1]
        with self.adapter.db() as c:
            self.assertEqual(c.execute('select cursor from subscriptions').fetchone()[0],0)
            c.execute('update subscriptions set retry=0')
        self.status=204; self.adapter.tick(lambda *a:True)
        self.assertEqual(eid,self.sent[-1][1])

    def test_unsubscribe_owner_isolation(self):
        self.subscribe()
        self.adapter.call('events/unsubscribe',self.params,('other','family','https://mcp.example'))
        with self.adapter.db() as c:
            self.assertEqual(c.execute('select count(*) from subscriptions').fetchone()[0],1)
        self.adapter.call('events/unsubscribe',self.params,self.principal)
        with self.adapter.db() as c:
            self.assertEqual(c.execute('select count(*) from subscriptions').fetchone()[0],0)

    def test_revoked_grant_no_delivery(self):
        self.subscribe(); self.items=[self.item(1)]; n=len(self.sent)
        self.adapter.tick(lambda *a:False)
        self.assertEqual(n,len(self.sent))
        with self.adapter.db() as c:
            self.assertEqual(c.execute('select count(*) from subscriptions').fetchone()[0],0)

    def test_expired_no_delivery(self):
        self.subscribe()
        with self.adapter.db() as c:c.execute('update subscriptions set expires=0')
        self.items=[self.item(1)]; n=len(self.sent); self.adapter.tick(lambda *a:True)
        self.assertEqual(n,len(self.sent))

    def test_permanent_failure_removed(self):
        for status in (410,413):
            self.subscribe(); self.items.append(self.item(len(self.items)+1)); self.status=status
            self.adapter.tick(lambda *a:True)
            with self.adapter.db() as c:
                self.assertEqual(c.execute('select count(*) from subscriptions').fetchone()[0],0)

    def test_failed_challenge_not_saved(self):
        self.adapter.send=lambda *a:(200,b'{"challenge":"wrong"}')
        with self.assertRaises(m.Fault) as error:self.subscribe()
        self.assertEqual(error.exception.code,-32015)
        with self.adapter.db() as c:self.assertEqual(c.execute('select count(*) from subscriptions').fetchone()[0],0)

    def test_arguments_and_key_validation(self):
        for change in ({'arguments':{'agent':'grokbot'}},{'name':'other'},{'ttlMs':True},{'cursor':'replay'}):
            params={**self.params,**change}
            with self.assertRaises(m.Fault):self.adapter.call('events/subscribe',params,self.principal)
        for key in ('secret','whsec_YQ==','whsec_!!!',None):
            with self.assertRaises(m.Fault):m.signing_key(key)

    def test_private_and_mixed_dns_rejected(self):
        self.dest.stop()
        for address in ('127.0.0.1','10.0.0.1','169.254.169.254','::1','::ffff:127.0.0.1'):
            with patch.object(m.socket,'getaddrinfo',return_value=[(2,1,6,'',(address,443))]):
                with self.assertRaises(m.Fault):m.destination('https://callback.example/hook')
        for url in ('http://example.com','https://user:pass@example.com','https://example.com:444/','https://example.com/#secret'):
            with self.assertRaises(m.Fault):m.destination(url)

    def test_partial_batch_checkpoints_each_accept(self):
        self.subscribe(); self.items=[self.item(1),self.item(2)]
        original=self.adapter.send
        self.adapter.send=lambda *args:(503,b'') if args[-1].get('data',{}).get('id')==2 else original(*args)
        self.adapter.tick(lambda *a:True)
        with self.adapter.db() as c:self.assertEqual(c.execute('select cursor from subscriptions').fetchone()[0],1)

    def test_standard_webhook_signature_exact_bytes(self):
        import urllib.parse
        with patch.object(m, 'destination', return_value=(urllib.parse.urlsplit('https://example.com/hook'),'8.8.8.8')):
            with patch.object(m.http.client,'HTTPSConnection') as factory:
                connection=factory.return_value
                connection.getresponse.return_value.status=200
                connection.getresponse.return_value.read.return_value=b'{}'
                key=self.params['delivery']['secret']
                m.post('https://example.com/hook',key,'sub_test','event_test',{'text':'测试'})
                args=connection.request.call_args.args
                body,headers=args[2:4]
                signed=b'event_test.'+headers['webhook-timestamp'].encode()+b'.'+body
                expected=base64.b64encode(hmac.new(m.signing_key(key),signed,hashlib.sha256).digest()).decode()
                self.assertEqual(headers['webhook-signature'],'v1,'+expected)
                self.assertEqual(headers['X-MCP-Subscription-Id'],'sub_test')

if __name__ == '__main__':unittest.main()
