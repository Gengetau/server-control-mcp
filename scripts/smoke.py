"""Isolated end-to-end smoke: real processes, random loopback ports, no public calls."""
import base64, hashlib, http.client, json, os
from pathlib import Path
import secrets, socket, subprocess, sys, tempfile, time, urllib.parse
from coding_tools_mcp import protocol

def port():
    with socket.socket() as s:
        s.bind(('127.0.0.1',0)); return s.getsockname()[1]

def closed(p):
    with socket.socket() as s:return s.connect_ex(('127.0.0.1',p)) != 0

def run():
    checks=[]
    def check(value,name):
        if not value:raise AssertionError(name)
        checks.append(name)
    with tempfile.TemporaryDirectory(prefix='scm-smoke-') as folder:
        root=Path(folder); bp,gp=port(),port()
        while gp==bp:gp=port()
        env=dict(os.environ)
        env.update(SCM_STATE_DIR=str(root/'state'),SCM_WORKSPACE=str(root/'workspace'),
            SCM_BACKEND_PORT=str(bp),SCM_GATEWAY_PORT=str(gp),SCM_PERMISSION_MODE='safe',SCM_EVENTS_ENABLED='1',
            CODING_TOOLS_MCP_SERVER_URL='https://mcp.example.test',
            CODING_TOOLS_MCP_OAUTH_PASSWORD=secrets.token_urlsafe(32),
            CODING_TOOLS_MCP_OAUTH_TOKEN_SECRET=secrets.token_hex(32),CODING_TOOLS_MCP_OAUTH_TOKEN_TTL='3600')
        process=None; log=(root/'private.log').open('wb')
        def stop():
            nonlocal process
            if process:
                process.terminate();process.wait(timeout=20)
                check(process.returncode==0,'supervisor shuts down cleanly');process=None
        def req(path,data=None,token=None,form=False,target=None,modern=False):
            headers={};body=None
            if data is not None:
                body=urllib.parse.urlencode(data).encode() if form else json.dumps(data).encode()
                headers['Content-Type']='application/x-www-form-urlencoded' if form else 'application/json'
            if token:headers['Authorization']='Bearer '+token
            if modern:
                headers['MCP-Protocol-Version']='2026-07-28'
                headers['Mcp-Method']=data['method']
                if data['params'].get('name'):
                    headers['Mcp-Name']=data['params']['name']
            c=http.client.HTTPConnection('127.0.0.1',target or gp,timeout=12)
            try:
                c.request('POST' if data is not None else 'GET',path,body,headers)
                r=c.getresponse();raw=r.read()
                content=json.loads(raw) if 'json' in r.getheader('Content-Type','') else None
                return r.status,r.headers,content
            finally:c.close()
        def start():
            nonlocal process
            process=subprocess.Popen([sys.executable,'-m','server_control_mcp','serve'],env=env,stdout=log,stderr=log)
            for _ in range(150):
                if process.poll() is not None:raise RuntimeError('service exited before readiness')
                try:
                    if req('/.well-known/oauth-authorization-server')[0]==200:return
                except OSError:pass
                time.sleep(.1)
            raise RuntimeError('gateway startup timeout')
        def rpc(method,params,token,modern=False):
            if modern:params={**params,'_meta':{protocol.META_PROTOCOL_VERSION:'2026-07-28',protocol.META_CLIENT_CAPABILITIES:{}}}
            status,_,result=req('/mcp',{'jsonrpc':'2.0','id':1,'method':method,'params':params},token,modern=modern)
            if status != 200 or 'result' not in result:
                raise AssertionError(f'RPC {method}: HTTP {status}, {result}')
            check(True,'RPC '+method)
            return result['result']
        def tool(name,args,token,modern=False):
            r=rpc('tools/call',{'name':name,'arguments':args},token,modern)
            check(not r.get('isError'),'tool '+name)
            return r.get('structuredContent',{})
        try:
            start()
            check(req('/mcp',{})[0]==401,'gateway denies unauthenticated requests')
            check(req('/mcp',{},target=bp)[0]==401,'backend denies unauthenticated requests')
            client=req('/oauth/register',{'redirect_uris':['http://127.0.0.1/callback']})[2]
            check('client_id' in client,'dynamic registration')
            verifier=secrets.token_urlsafe(48)
            challenge=base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b'=').decode()
            origin=env['CODING_TOOLS_MCP_SERVER_URL']
            auth={'client_id':client['client_id'],'redirect_uri':'http://127.0.0.1/callback','resource':origin,
                  'code_challenge':challenge,'code_challenge_method':'S256','state':'smoke'}
            check(req('/oauth/authorize',{**auth,'password':'wrong'},form=True)[0]!=302,'wrong password denied')
            status,headers,_=req('/oauth/authorize',{**auth,'password':env['CODING_TOOLS_MCP_OAUTH_PASSWORD']},form=True)
            check(status==302,'PKCE authorization')
            code=urllib.parse.parse_qs(urllib.parse.urlsplit(headers['Location']).query)['code'][0]
            exchange={'grant_type':'authorization_code','client_id':client['client_id'],'code':code,
                      'redirect_uri':auth['redirect_uri'],'resource':origin,'code_verifier':verifier}
            stop();start()
            status,_,tokens=req('/oauth/token',exchange,form=True)
            check(status==200 and 'refresh_token' in tokens,'pending code survives restart')
            check(req('/oauth/token',exchange,form=True)[0]==400,'authorization code single use')
            token=tokens['access_token']
            catalog=rpc('tools/list',{},token)
            check(len(catalog['tools'])==18,'upstream tool catalog intact')
            info=tool('server_info',{},token)
            check(info['gateway']['auth']=='oauth' and info['permission_mode']=='safe','real executor safe mode')
            check('events' in rpc('server/discover',{},token,True)['capabilities'],'modern event discovery')
            check(rpc('events/list',{},token,True)['events'][0]['name']=='server.changed','event catalog')
            check(tool('server_info',{},token,True)['gateway']['events'],'modern tool forwarding')
            outside=rpc('tools/call',{'name':'read_file','arguments':{'path':'../state/oauth.sqlite3'}},token)
            check(outside.get('isError'),'workspace escape rejected')
            tool('apply_patch',{'patch':'*** Begin Patch\n*** Add File: hello.txt\n+hello from smoke\n*** End Patch'},token)
            check(tool('read_file',{'path':'hello.txt'},token)['content'].strip()=='hello from smoke','patch/read roundtrip')
            check(tool('exec_command',{'cmd':'pwd','workdir':'.'},token)['exit_code']==0,'real command execution')
            stop();start();tool('server_info',{},token)
            status,_,fresh=req('/oauth/token',{'grant_type':'refresh_token','client_id':client['client_id'],
                                              'refresh_token':tokens['refresh_token']},form=True)
            check(status==200,'refresh after process restart')
            check(fresh['refresh_token']!=tokens['refresh_token'],'refresh token rotates')
            req('/oauth/revoke',{'client_id':client['client_id'],'token':fresh['refresh_token']},form=True)
            check(req('/mcp',{},fresh['access_token'])[0]==401,'revocation rejects new access')
            check(req('/mcp',{},token)[0]==401,'revocation rejects old family access')
            stop();check(closed(bp) and closed(gp),'both listeners stop')
        finally:stop();log.close()
    print(json.dumps({'ok':True,'checks':len(checks),'passed':checks},indent=2))
if __name__=='__main__':run()
