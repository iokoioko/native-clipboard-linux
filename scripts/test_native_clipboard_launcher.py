#!/usr/bin/python
"""Exercise network recovery without changing the desktop network or environment."""
import json
from pathlib import Path
import runpy
import subprocess
import tempfile
import unittest
from unittest.mock import patch

LAUNCHER = Path(__file__).with_name('native-clipboard-run.py')


class LauncherRecovery(unittest.TestCase):
    def test_waits_through_missing_interface_and_address_then_uses_current_address(self):
        with tempfile.TemporaryDirectory() as root:
            home = Path(root)
            cfg = home / '.config/native-clipboard'
            cfg.mkdir(parents=True)
            private = home / 'private'
            private.write_text('fixture')
            (cfg / 'config.json').write_text(json.dumps({
                'interface': 'test-interface', 'identity': str(private),
                'bonjour': str(private), 'ids_identifier': str(private),
            }))
            responses = [
                subprocess.CalledProcessError(1, ['ip']),
                subprocess.CompletedProcess(['ip'], 0, b'[]'),
                subprocess.CompletedProcess(['ip'], 0, json.dumps([
                    {'addr_info': [{'scope': 'global', 'local': '192.0.2.99'}]}
                ]).encode()),
            ]
            with patch.object(Path, 'home', return_value=home), \
                 patch('subprocess.run', side_effect=responses) as probe, \
                 patch('time.sleep') as sleep, patch('os.execv') as execute:
                runpy.run_path(str(LAUNCHER), run_name='__main__')
            self.assertEqual(probe.call_count, 3)
            self.assertEqual([c.args for c in sleep.call_args_list], [(5,), (5,)])
            binary, args = execute.call_args.args
            self.assertEqual(binary, home / '.local/lib/native-clipboard/ac-dc')
            self.assertEqual(args[args.index('--bind') + 1], '192.0.2.99')
            self.assertIn('--continuous', args)
            self.assertIn('--copy-verified-text', args)
            self.assertEqual(args[args.index('--iface') + 1], 'test-interface')


if __name__ == '__main__':
    unittest.main()
