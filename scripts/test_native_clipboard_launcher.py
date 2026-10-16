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
    def run_config(self, extras):
        with tempfile.TemporaryDirectory() as root:
            home = Path(root)
            cfg = home / '.config/native-clipboard'
            cfg.mkdir(parents=True)
            private = home / 'private'
            private.write_text('ab' * 32)
            config = {'interface': 'test-interface', 'identity': str(private),
                      'bonjour': str(private), 'ids_identifier': str(private)}
            config.update({key: str(private) for key in extras})
            (cfg / 'config.json').write_text(json.dumps(config))
            response = subprocess.CompletedProcess(['ip'], 0, json.dumps([
                {'addr_info': [{'scope': 'global', 'local': '192.0.2.99'}]}
            ]).encode())
            with patch.object(Path, 'home', return_value=home), \
                 patch('subprocess.run', return_value=response), \
                 patch('os.execv') as execute:
                runpy.run_path(str(LAUNCHER), run_name='__main__')
            return execute.call_args.args[1]

    def test_ble_opt_in_uses_exact_signer_and_no_legacy_probe_flags(self):
        args = self.run_config(['ble_keys', 'peer_signing_fingerprint_file'])
        self.assertEqual(args[1], 'ble-listen-probe')
        self.assertEqual(args[args.index('--peer-signing-fingerprint') + 1], 'ab' * 32)
        self.assertIn('--continuous', args)
        self.assertIn('--copy-verified-text', args)
        self.assertNotIn('--probe-pasteboard-data', args)

    def test_partial_ble_configuration_fails_before_launch(self):
        for field in ['ble_keys', 'peer_signing_fingerprint_file']:
            with self.subTest(field=field), self.assertRaises(SystemExit):
                self.run_config([field])

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
