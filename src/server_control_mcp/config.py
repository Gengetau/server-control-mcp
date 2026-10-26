"""Validated deployment settings; no production credentials or locations."""
from dataclasses import dataclass
import os
from pathlib import Path
import urllib.parse

@dataclass(frozen=True)
class Settings:
    state_dir: Path
    workspace: Path
    origin: str
    backend_port: int
    gateway_port: int
    permission_mode: str
    events_enabled: bool

    @classmethod
    def load(cls):
        state = Path(os.environ.get('SCM_STATE_DIR', './state')).resolve()
        workspace = Path(os.environ.get('SCM_WORKSPACE', './workspace')).resolve()
        origin = os.environ.get('CODING_TOOLS_MCP_SERVER_URL', '').rstrip('/')
        p = urllib.parse.urlsplit(origin)
        if (p.scheme != 'https' or not p.hostname or p.username or p.password
                or p.query or p.fragment or p.path or any(c.isspace() for c in origin)):
            raise ValueError('CODING_TOOLS_MCP_SERVER_URL must be an HTTPS origin without a path')
        try:
            p.port
        except ValueError:
            raise ValueError('Invalid public origin port') from None
        ports = [int(os.environ.get(k, str(v))) for k,v in
                 [('SCM_BACKEND_PORT',28766),('SCM_GATEWAY_PORT',28767)]]
        if any(not 1024 <= port <= 65535 for port in ports) or ports[0] == ports[1]:
            raise ValueError('Ports must be distinct and between 1024 and 65535')
        mode = os.environ.get('SCM_PERMISSION_MODE', 'safe')
        if mode not in ('safe','trusted','dangerous'):
            raise ValueError('Unknown permission mode')
        if state == workspace or state.is_relative_to(workspace):
            raise ValueError('State directory must be outside the executor workspace')
        for key in ('CODING_TOOLS_MCP_OAUTH_PASSWORD','CODING_TOOLS_MCP_OAUTH_TOKEN_SECRET'):
            if len(os.environ.get(key, '')) < 32:
                raise ValueError(key+' must contain at least 32 characters; run init')
        enabled = os.environ.get('SCM_EVENTS_ENABLED', '0')
        if enabled not in ('0', '1'):
            raise ValueError('SCM_EVENTS_ENABLED must be 0 or 1')
        return cls(state, workspace, origin, *ports, mode, enabled == '1')


def load_env(path):
    """Read literal KEY=value lines; never execute shell syntax or expand secrets."""
    for number, line in enumerate(Path(path).read_text().splitlines(), 1):
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        key, sep, value = line.partition('=')
        if not sep or not key.isidentifier():
            raise ValueError(f'Invalid environment file line {number}')
        os.environ[key] = value
