import os
from pathlib import Path
import tempfile,unittest
from unittest.mock import patch
from server_control_mcp.config import Settings,load_env
from server_control_mcp.cli import initialize
from server_control_mcp.events import EventFeed

class ConfigurationTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
        self.values={'CODING_TOOLS_MCP_SERVER_URL':'https://mcp.example.test',
            'CODING_TOOLS_MCP_OAUTH_PASSWORD':'x'*40,'CODING_TOOLS_MCP_OAUTH_TOKEN_SECRET':'y'*64,
            'SCM_STATE_DIR':str(self.root/'state'),'SCM_WORKSPACE':str(self.root/'workspace')}
    def load(self,**extra):
        with patch.dict(os.environ,{**self.values,**extra},clear=True):return Settings.load()
    def test_defaults_and_state_boundary(self):
        self.assertEqual(self.load().permission_mode,'safe');self.assertFalse(self.load().events_enabled)
        with self.assertRaises(ValueError):self.load(SCM_STATE_DIR=str(self.root/'workspace'/'private'))
        (self.root/'workspace').mkdir();(self.root/'alias').symlink_to(self.root/'workspace',target_is_directory=True)
        with self.assertRaises(ValueError):self.load(SCM_STATE_DIR=str(self.root/'alias'/'state'))
    def test_origin_ports_and_credentials(self):
        for origin in ['http://example.test','https://example.test/path','https://u:p@example.test',
                       'https://example.test?secret=a','https://example.test/#x','']:
            with self.subTest(origin=origin),self.assertRaises(ValueError):self.load(CODING_TOOLS_MCP_SERVER_URL=origin)
        for extra in [{'SCM_BACKEND_PORT':'28767'},{'SCM_GATEWAY_PORT':'80'},
                      {'SCM_PERMISSION_MODE':'unknown'},{'SCM_EVENTS_ENABLED':'true'},
                      {'CODING_TOOLS_MCP_OAUTH_PASSWORD':'short'}]:
            with self.subTest(extra=extra),self.assertRaises(ValueError):self.load(**extra)
    def test_init_does_not_overwrite_and_env_is_literal(self):
        path=self.root/'private.env';initialize(path);original=path.read_bytes()
        with self.assertRaises(FileExistsError):initialize(path)
        self.assertEqual(path.read_bytes(),original);self.assertEqual(path.stat().st_mode & 0o777,0o600)
        path.write_text('EXAMPLE=$(do-not-execute)\n')
        with patch.dict(os.environ,{},clear=True):
            load_env(path);self.assertEqual(os.environ['EXAMPLE'],'$(do-not-execute)')
    def test_outbox_is_durable_and_monotonic(self):
        path=self.root/'outbox.sqlite3';a=EventFeed(path);first=a.emit('task.assigned','client-one')
        b=EventFeed(path);second=b.emit('task.updated','client-two');self.assertGreater(second,first)
        self.assertEqual(b(first)['events'][0]['recipient'],'client-two')
        self.assertTrue(b(first)['events'][0]['at'].endswith('+00:00'))
        with self.assertRaises(ValueError):b.emit('','client')
        with self.assertRaises(ValueError):b.emit('task.updated','')
if __name__=='__main__':unittest.main()
