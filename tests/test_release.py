import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

path = Path(__file__).resolve().parents[1] / 'scripts' / 'release.py'
spec = importlib.util.spec_from_file_location('release_script', path)
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)


class ReleaseTests(unittest.TestCase):
    def test_allowlist_excludes_runtime_git_and_credentials(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            for name in ('src', 'state', '.git'):
                (root/name).mkdir()
            (root/'README.md').write_text('public')
            (root/'src'/'module.py').write_text('value = 1\n')
            (root/'.env').write_text('private')
            (root/'state'/'oauth.sqlite3').write_bytes(b'private')
            (root/'.git'/'config').write_text('private')
            with patch.object(release, 'ROOT', root), patch.object(release, 'TOP', {'README.md'}), patch.object(release, 'TREE', {'src': {'.py'}}):
                selected = {p.relative_to(root).as_posix() for p in release.selected()}
                self.assertEqual(selected, {'README.md', 'src/module.py'})
                (root/'src'/'module.py').write_text('credential = "'+'ghp_'+'A'*36+'"\n')
                with self.assertRaises(ValueError):
                    release.selected()

    def test_local_denylist_extends_patterns(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root/'README.md').write_text('deployed on internal-host-01\n')
            with patch.object(release, 'ROOT', root), patch.object(release, 'TOP', {'README.md'}), patch.object(release, 'TREE', {}):
                self.assertEqual(len(release.selected()), 1)
                (root/release.DENYLIST).write_text('# private identifiers\ninternal-host-\\d+\n')
                with self.assertRaises(ValueError):
                    release.selected()

    def test_symlinked_top_level_file_is_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root/'secret').write_text('private')
            (root/'README.md').symlink_to(root/'secret')
            with patch.object(release, 'ROOT', root), patch.object(release, 'TOP', {'README.md'}), patch.object(release, 'TREE', {}):
                with self.assertRaises(ValueError):
                    release.selected()


if __name__ == '__main__':
    unittest.main()
