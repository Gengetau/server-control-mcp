"""OAuth facade and optional MCP Events; execution stays in the upstream runtime.

Modified for public release: configurable ports, authenticated backend forwarding,
revocable OAuth event principals, generic feed, bounded lifecycle.
"""
from __future__ import annotations
import copy
import http.client
import json
import os
from pathlib import Path
from coding_tools_mcp import server as upstream, protocol
from .config import Settings
from .persistent_oauth import PersistentOAuthMixin, install_persistence, decode_access, valid_access
from .events import Events, EventFeed, Fault

MAX_RESPONSE_BYTES = 64 * 1024 * 1024
FORWARDED_HEADERS = ('Accept','MCP-Protocol-Version','Mcp-Method','Mcp-Name')

class GatewayHandler(PersistentOAuthMixin, upstream.MCPHandler):
    def log_message(self, *args):
        pass  # Never include OAuth codes, tokens or callback URLs in access logs.

    def handle_rpc(self, request, *, transport_protocol_version=None):
        method = request.get('method', '')
        params = request.get('params') or {}
        modern = protocol.request_era(method, params) == protocol.MODERN_ERA
        events = getattr(self.runtime, 'scm_events', None)
        if events is not None and (method == 'server/discover' or method.startswith('events/')):
            if 'id' not in request:
                return None
            try:
                if not modern:
                    raise Fault(-32602, 'MCP Events requires protocol 2026-07-28 metadata')
                if method == 'server/discover':
                    result = {'supportedVersions':['2026-07-28'], 'capabilities':{'tools':{},'events':{}}}
                else:
                    # Defense in depth: re-check the bearer grant, including revocation.
                    header = self.headers.get('Authorization','').strip()
                    cfg, origin = self.runtime.oauth_config, self.oauth_base_url()
                    if not header.startswith('Bearer ') or not valid_access(header[7:], cfg, origin):
                        raise Fault(-32001, 'Unauthorized', 'invalid_token')
                    claims = decode_access(header[7:], cfg, origin)
                    principal = (claims['client_id'], claims['sid'], self.oauth_base_url())
                    result = events.call(method, params, principal)
                result = protocol.shape_result(protocol.modern_request_context(params), method,
                                               result, self.runtime.server_identity())
                return {'jsonrpc':'2.0','id':request['id'],'result':result}
            except Fault as error:
                body = {'code':error.code,'message':error.message}
                if error.reason:
                    body['data'] = {'reason':error.reason}
                return {'jsonrpc':'2.0','id':request['id'],'error':body}
            except Exception:
                return upstream.jsonrpc_error(request['id'], -32603, 'Event adapter unavailable')
        forwarded = copy.deepcopy(request)
        headers = {'Content-Type':'application/json',
                   'Authorization':'Bearer '+self.runtime.scm_backend_token}
        # The facade shapes modern results itself, matching the private adapter.
        if modern:
            forwarded.setdefault('params', {}).pop('_meta', None)
        else:
            for name in FORWARDED_HEADERS:
                if self.headers.get(name) is not None:
                    headers[name] = self.headers[name]
        connection = http.client.HTTPConnection('127.0.0.1', self.runtime.scm_backend_port, timeout=360)
        try:
            connection.request('POST','/mcp',json.dumps(forwarded).encode(),headers)
            response = connection.getresponse()
            payload = response.read(MAX_RESPONSE_BYTES+1)
            if response.status == 202 and not payload:
                return None
            if len(payload) > MAX_RESPONSE_BYTES:
                raise ValueError('upstream response limit')
            parsed = json.loads(payload)
            if not isinstance(parsed, dict) or parsed.get('jsonrpc') != '2.0':
                raise ValueError('invalid upstream response')
            result = parsed.get('result')
            if isinstance(result, dict):
                if method == 'tools/call' and params.get('name') == 'server_info':
                    info = result.get('structuredContent')
                    if isinstance(info, dict):
                        info['gateway'] = {'name':'server-control-mcp','version':'0.1.0',
                                           'auth':'oauth','events':events is not None}
                if modern:
                    parsed['result'] = protocol.shape_result(protocol.modern_request_context(params),
                        method,result,self.runtime.server_identity())
            return parsed
        except (OSError,ValueError,http.client.HTTPException):
            return upstream.jsonrpc_error(request.get('id'),-32603,'Execution backend unavailable')
        finally:
            connection.close()


BaseHTTPServer = upstream.RuntimeHTTPServer

class GatewayHTTPServer(BaseHTTPServer):
    def __init__(self, address, handler, runtime):
        if address[0] != '127.0.0.1':
            raise ValueError('Gateway must bind loopback behind an HTTPS ingress')
        settings = Settings.load()
        runtime.scm_backend_port = settings.backend_port
        runtime.scm_backend_token = os.environ['SCM_BACKEND_TOKEN']
        runtime.scm_events = None
        super().__init__(address, handler, runtime)
        if settings.events_enabled:
            feed = EventFeed(settings.state_dir/'outbox.sqlite3')
            runtime.scm_events = Events(settings.state_dir/'subscriptions.sqlite3', read_feed=feed)
            runtime.scm_events.start(runtime.oauth_config.registry.store.active)

    def server_close(self):
        events = getattr(self.runtime,'scm_events',None)
        if events is not None:
            events.stop.set()
        super().server_close()


def main():
    settings = Settings.load()
    os.umask(0o077)
    settings.state_dir.mkdir(parents=True,exist_ok=True,mode=0o700)
    scratch = settings.state_dir/'gateway'
    scratch.mkdir(exist_ok=True,mode=0o700)
    os.environ['MCP_OAUTH_STATE_DB'] = str(settings.state_dir/'oauth.sqlite3')
    os.environ['CODING_TOOLS_MCP_AUTH_MODE'] = 'oauth'
    os.environ['CODING_TOOLS_MCP_TELEMETRY'] = 'off'
    install_persistence()
    upstream.MCPHandler = GatewayHandler
    upstream.RuntimeHTTPServer = GatewayHTTPServer
    return upstream.main(['--workspace',str(scratch),'--host','127.0.0.1',
        '--port',str(settings.gateway_port),'--oauth-mode','--permission-mode','safe'])
