"""Build a deterministic allowlisted source ZIP; never walk private runtime state."""
import argparse,hashlib,json,re,zipfile
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
TOP={'pyproject.toml','MANIFEST.in','README.md','README.en.md','LICENSE','NOTICE',
     'CHANGELOG.md','SECURITY.md','CONTRIBUTING.md','.env.example','.gitignore',
     '.dockerignore','Dockerfile','compose.yaml'}
TREE={'src':{'.py'},'tests':{'.py'},'scripts':{'.py'},'docs':{'.md','.json'},
      'deploy':{'.service'},'.github/workflows':{'.yml'}}

# Generic credential forms. Deployment-specific identifiers (hostnames, paths, VPN
# names) belong in an untracked local file, one regex per line, so they are never published.
PATTERNS=[r'-----BEGIN (?:RSA |OPENSSH |EC |DSA )?PRIVATE KEY-----',r'\bgh[pousr]_[A-Za-z0-9]{30,}',
          r'\bgithub_pat_[A-Za-z0-9_]{40,}',r'\bsk-(?:proj-)?[A-Za-z0-9_-]{32,}',r'\btskey-[A-Za-z0-9-]{20,}',
          r'\bAKIA[0-9A-Z]{16}\b',r'\bxox[baprs]-[A-Za-z0-9-]{10,}']
DENYLIST='.release-denylist'

def patterns():
    extra=ROOT/DENYLIST
    local=[]
    if extra.is_file():
        local=[l.strip() for l in extra.read_text().splitlines() if l.strip() and not l.lstrip().startswith('#')]
    return [re.compile(p) for p in PATTERNS+local]

def selected():
    compiled=patterns()
    paths=[ROOT/name for name in sorted(TOP)]
    for folder,suffixes in TREE.items():
        paths.extend(p for p in (ROOT/folder).rglob('*') if p.is_file() and p.suffix in suffixes
                     and '__pycache__' not in p.parts and not p.is_symlink())
    paths=sorted(set(paths))
    for p in paths:
        if not p.is_file() or p.is_symlink():raise ValueError('Missing or symlinked release file: '+str(p.relative_to(ROOT)))
        text=p.read_text()
        if any(pattern.search(text) for pattern in compiled):
            raise ValueError('Potential private content in '+str(p.relative_to(ROOT)))
    return paths

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--check-only',action='store_true');args=parser.parse_args()
    paths=selected()
    if args.check_only:
        print(json.dumps({'ok':True,'allowlisted_files':len(paths),'private_pattern_scan':'passed'}));return
    dest=ROOT/'dist';dest.mkdir(exist_ok=True)
    archive=dest/'server-control-mcp-0.1.0-source.zip'
    with zipfile.ZipFile(archive,'w',compression=zipfile.ZIP_DEFLATED) as z:
        for p in paths:
            info=zipfile.ZipInfo('server-control-mcp/'+p.relative_to(ROOT).as_posix(),date_time=(2026,10,26,0,0,0))
            info.compress_type=zipfile.ZIP_DEFLATED;info.external_attr=0o100644<<16
            z.writestr(info,p.read_bytes())
    digest=hashlib.sha256(archive.read_bytes()).hexdigest()
    (dest/(archive.name+'.sha256')).write_text(digest+'  '+archive.name+'\n')
    print(json.dumps({'ok':True,'archive':str(archive),'files':len(paths),'sha256':digest}))
if __name__=='__main__':main()
