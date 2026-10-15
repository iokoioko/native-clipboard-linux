#!/usr/bin/env python3
"""Verify first-install bootstrap and reinstall preservation without system changes."""
import json
from pathlib import Path
import runpy
import tempfile
import unittest
from unittest.mock import patch

INSTALLER = Path(__file__).with_name('install-native-clipboard.py')


class InstallerTests(unittest.TestCase):
    def test_explicit_bootstrap_then_preserves_existing_configuration(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            home = root / 'home'
            home.mkdir()
            bootstrap = root / 'private.json'
            bootstrap.write_text('{}')
            binary = root / 'ac-dc'
            binary.write_bytes(b'test-binary')
            supplied = root / 'config.json'
            configuration = {'interface': 'example-interface', **{
                key: str(bootstrap) for key in ('identity', 'bonjour', 'ids_identifier')
            }}
            supplied.write_text(json.dumps(configuration))
            with patch.object(Path, 'home', return_value=home), \
                 patch('subprocess.run') as commands, \
                 patch('sys.argv', [str(INSTALLER), '--config', str(supplied), '--binary', str(binary)]):
                runpy.run_path(str(INSTALLER), run_name='__main__')
            installed = home / '.config/native-clipboard/config.json'
            self.assertEqual(json.loads(installed.read_text()), configuration)
            self.assertEqual(installed.stat().st_mode & 0o777, 0o600)
            self.assertEqual((home / '.local/lib/native-clipboard/ac-dc').read_bytes(), b'test-binary')
            self.assertFalse(any('enable' in call.args[0] or 'start' in call.args[0]
                                 for call in commands.call_args_list))
            configuration['interface'] = 'preserved-interface'
            installed.write_text(json.dumps(configuration))
            with patch.object(Path, 'home', return_value=home), \
                 patch('subprocess.run'), \
                 patch('sys.argv', [str(INSTALLER), '--config', str(supplied), '--binary', str(binary)]):
                runpy.run_path(str(INSTALLER), run_name='__main__')
            self.assertEqual(json.loads(installed.read_text()), configuration)


if __name__ == '__main__':
    unittest.main()
