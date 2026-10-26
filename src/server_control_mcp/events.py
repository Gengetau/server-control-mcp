"""MCP Events webhook delivery, generalized from the private deployment.
Modified for public release: generic recipients, UTC timestamps, SQLite event source.
"""
import base64
from contextlib import contextmanager
import datetime as dt
import hashlib
import hmac
import http.client
import ipaddress
import json
import os
from pathlib import Path
import secrets
import socket
import sqlite3
import ssl
import threading
import time
import urllib.parse
import urllib.request

EVENT = 'server.changed'
CATALOG = {'events': [{'name': EVENT,
    'description': 'Directed server events; notification delivery does not acknowledge task completion.',
    'delivery': ['webhook'],
    'inputSchema': {'type': 'object', 'properties': {}, 'additionalProperties': False},
    'payloadSchema': {'type': 'object', 'properties': {
        'id': {'type': 'integer'}, 'kind': {'type': 'string'}, 'at': {'type': 'string'}},
        'required': ['id', 'kind', 'at'], 'additionalProperties': False}}]}


class Fault(Exception):
    def __init__(self, code, message, reason=None):
        self.code, self.message, self.reason = code, message, reason


def signing_key(secret):
    try:
        if not isinstance(secret, str) or not secret.startswith('whsec_'):
            raise ValueError()
        key = base64.b64decode(secret[6:], validate=True)
        if not 24 <= len(key) <= 64:
            raise ValueError()
        return key
    except (ValueError, TypeError):
        raise Fault(-32602, 'Invalid webhook signing key') from None


def destination(url):
    try:
        p = urllib.parse.urlsplit(url)
        if (p.scheme != 'https' or not p.hostname or p.username or p.password
                or p.fragment or p.port not in (None, 443) or len(url) > 4096
                or any(ord(c) < 33 or ord(c) > 126 for c in url)):
            raise ValueError()
        addresses = socket.getaddrinfo(p.hostname, 443, type=socket.SOCK_STREAM)
        if not addresses or any(not ipaddress.ip_address(a[4][0]).is_global for a in addresses):
            raise ValueError()
        return p, addresses[0][4][0]
    except (ValueError, TypeError, OSError):
        raise Fault(-32602, 'Callback must resolve exclusively to public HTTPS addresses') from None


def post(url, secret, subscription, event_id, payload):
    p, address = destination(url)  # re-resolve and pin on every connection
    body = json.dumps(payload, ensure_ascii=False, separators=(',', ':')).encode()
    if len(body) > 262144:
        raise Fault(-32602, 'Event too large')
    timestamp = str(int(time.time()))
    signature = base64.b64encode(hmac.new(signing_key(secret),
        event_id.encode()+b'.'+timestamp.encode()+b'.'+body, hashlib.sha256).digest()).decode()
    connection = http.client.HTTPSConnection(p.hostname, 443, timeout=10)
    # Use only the validated IP while preserving the hostname for SNI/certificate checks.
    def connect():
        raw = socket.create_connection((address, 443), timeout=10)
        try:
            connection.sock = ssl.create_default_context().wrap_socket(raw, server_hostname=p.hostname)
        except BaseException:
            raw.close()
            raise
    connection.connect = connect
    try:
        connection.request('POST', urllib.parse.urlunsplit(('', '', p.path or '/', p.query, '')),
            body, {'Content-Type': 'application/json', 'webhook-id': event_id,
                   'webhook-timestamp': timestamp, 'webhook-signature': 'v1,'+signature,
                   'X-MCP-Subscription-Id': subscription})
        response = connection.getresponse()
        data = response.read(8193)
        return response.status, data
    finally:
        connection.close()


class EventFeed:
    """Local-only outbox. Only explicitly addressed OAuth client IDs receive events."""
    def __init__(self, path):
        self.path = str(path)
        Path(path).parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with sqlite3.connect(self.path) as db:
            db.execute('CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY AUTOINCREMENT, kind TEXT NOT NULL, at TEXT NOT NULL, recipient TEXT NOT NULL)')
        os.chmod(self.path, 0o600)

    def emit(self, kind, recipient):
        if not isinstance(kind, str) or not kind or len(kind) > 128:
            raise ValueError('kind must contain 1 to 128 characters')
        if not isinstance(recipient, str) or not recipient or len(recipient) > 512:
            raise ValueError('recipient must be an OAuth client ID')
        at = dt.datetime.now(dt.timezone.utc).isoformat()
        with sqlite3.connect(self.path) as db:
            row = db.execute('INSERT INTO events(kind,at,recipient) VALUES(?,?,?)', (kind, at, recipient))
            return row.lastrowid

    def __call__(self, after):
        with sqlite3.connect(self.path) as db:
            db.row_factory = sqlite3.Row
            items = [dict(r) for r in db.execute('SELECT * FROM events WHERE id>? ORDER BY id LIMIT 50', (after,))]
        return {'events': items, 'next_after': items[-1]['id'] if items else after}

def empty_feed(after):
    return {'events': [], 'next_after': after}


class Events:
    def __init__(self, path='state/subscriptions.sqlite3', read_feed=empty_feed, send=post):
        self.path, self.read_feed, self.send = str(path), read_feed, send
        self.lock = threading.RLock()
        self.stop = threading.Event()
        Path(path).parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with self.db() as c:
            c.execute('''CREATE TABLE IF NOT EXISTS subscriptions
                (id TEXT PRIMARY KEY, owner TEXT, family TEXT, origin TEXT, url TEXT,
                 secret TEXT, expires REAL, cursor INTEGER, retry REAL DEFAULT 0,
                 failures INTEGER DEFAULT 0)''')
        os.chmod(path, 0o600)

    @contextmanager
    def db(self):
        connection = sqlite3.connect(self.path, timeout=10)
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    def baseline(self):
        after = 0
        for _ in range(1000):
            page = self.read_feed(after)
            if not page['events']:
                return after
            next_after = page['next_after']
            if next_after <= after:
                raise ValueError('Feed cursor did not advance')
            after = next_after
        raise ValueError('Feed baseline limit')

    def call(self, method, params, principal):
        owner, family, origin = principal
        if method == 'events/list':
            if set(params) - {'_meta', 'cursor'} or params.get('cursor') is not None:
                raise Fault(-32602, 'Invalid event catalog cursor')
            return CATALOG
        if method not in ('events/subscribe', 'events/unsubscribe'):
            raise Fault(-32601, 'Unknown event method')
        allowed = {'_meta', 'name', 'arguments', 'delivery', 'cursor', 'ttlMs'}
        delivery = params.get('delivery', {})
        if (set(params) - allowed or params.get('name') != EVENT
                or params.get('arguments', {}) != {} or not isinstance(delivery, dict)
                or delivery.get('mode') != 'webhook' or params.get('cursor') is not None):
            raise Fault(-32602, 'Invalid event or subscription arguments')
        url = delivery.get('url')
        if not isinstance(url, str):
            raise Fault(-32602, 'Missing callback URL')
        identity = json.dumps([owner, origin, url, EVENT, {}], separators=(',', ':'))
        sid = 'sub_'+hashlib.sha256(identity.encode()).hexdigest()[:40]
        if method == 'events/unsubscribe':
            with self.lock, self.db() as c:
                c.execute('DELETE FROM subscriptions WHERE id=? AND owner=?', (sid, owner))
            return {}
        if not family:
            raise Fault(-32602, 'Reauthorize MCP to enable revocable event subscriptions')
        if set(delivery) != {'mode', 'url', 'secret'}:
            raise Fault(-32602, 'Invalid delivery fields')
        secret = delivery.get('secret')
        signing_key(secret)
        destination(url)
        ttl = params.get('ttlMs', 86400000)
        if isinstance(ttl, bool) or not isinstance(ttl, int) or ttl <= 0:
            raise Fault(-32602, 'Invalid ttlMs')
        ttl = min(ttl, 7*86400000)
        # Serialize subscribe/unsubscribe with delivery: removed subscriptions cannot be resurrected.
        with self.lock:
            with self.db() as c:
                old = c.execute('SELECT cursor,expires FROM subscriptions WHERE id=?', (sid,)).fetchone()
                count = c.execute('SELECT count(*) FROM subscriptions WHERE expires>?', (time.time(),)).fetchone()[0]
            if not old and count >= 16:
                raise Fault(-32602, 'Subscription limit reached')
            cursor = old[0] if old and old[1] > time.time() else self.baseline()
            challenge = secrets.token_urlsafe(32)
            try:
                status, body = self.send(url, secret, sid, 'verify_'+secrets.token_hex(16),
                                         {'type': 'verification', 'challenge': challenge})
                echoed = json.loads(body).get('challenge')
                if not 200 <= status < 300 or not isinstance(echoed, str) or not hmac.compare_digest(echoed, challenge):
                    raise ValueError()
            except Exception:
                raise Fault(-32015, 'Callback verification failed', 'challenge_failed') from None
            expires = time.time()+ttl/1000
            with self.db() as c:
                c.execute('INSERT OR REPLACE INTO subscriptions VALUES(?,?,?,?,?,?,?,?,0,0)',
                          (sid, owner, family, origin, url, secret, expires, cursor))
        return {'id': sid, 'refreshBefore': dt.datetime.fromtimestamp(expires, dt.timezone.utc).isoformat(),
                'cursor': None, 'truncated': False}

    def tick(self, authorized):
        with self.lock, self.db() as c:
            c.execute('DELETE FROM subscriptions WHERE expires<=?', (time.time(),))
            rows = c.execute('SELECT * FROM subscriptions WHERE retry<=?', (time.time(),)).fetchall()
            for row in rows:
                sid, owner, family, origin, url, secret, expires, cursor, _, failures = row
                if not authorized(family, owner, origin):
                    c.execute('DELETE FROM subscriptions WHERE id=?', (sid,))
                    continue
                try:
                    page = self.read_feed(cursor)  # authorization is rechecked before delivery
                    for item in page['events'][:50]:
                        if expires <= time.time() or not authorized(family, owner, origin):
                            c.execute('DELETE FROM subscriptions WHERE id=?', (sid,))
                            break
                        if item.get('recipient') != owner:
                            cursor = item['id']
                            c.execute('UPDATE subscriptions SET cursor=? WHERE id=?', (cursor, sid))
                            c.commit()  # delivery cursor only; never ACK collaboration work
                            continue
                        data = {k: item[k] for k in ('id', 'kind', 'at')}
                        occurred = dt.datetime.fromisoformat(item['at']).isoformat()
                        eid = sid+'_'+str(item['id'])
                        status, _ = self.send(url, secret, sid, eid,
                            {'eventId': eid, 'name': EVENT, 'timestamp': occurred, 'data': data, 'cursor': None})
                        if status in (410, 413):
                            c.execute('DELETE FROM subscriptions WHERE id=?', (sid,))
                            break
                        if not 200 <= status < 300:
                            raise ValueError('Delivery rejected')
                        cursor = item['id']
                        c.execute('UPDATE subscriptions SET cursor=?,failures=0,retry=0 WHERE id=?', (cursor,sid))
                        c.commit()  # checkpoint every accepted event, never acknowledge the task feed
                    else:
                        continue
                except Exception:
                    failures += 1
                    if failures >= 12:
                        c.execute('DELETE FROM subscriptions WHERE id=?', (sid,))
                    else:
                        c.execute('UPDATE subscriptions SET failures=?,retry=? WHERE id=?',
                                  (failures,time.time()+min(3600,30*2**min(failures,7)),sid))

    def start(self, authorized):
        def run():
            while not self.stop.wait(30):
                try:
                    self.tick(authorized)
                except Exception:
                    pass  # Never log callback URLs, payloads, tokens or signing keys.
        threading.Thread(target=run, name='mcp-events', daemon=True).start()
