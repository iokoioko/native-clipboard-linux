#!/usr/bin/python
"""Resolve the current Wi-Fi address before starting the clipboard listener."""
import ipaddress
import json
import os
import re
from pathlib import Path
import subprocess
import time

base = Path.home() / '.config/native-clipboard'
config = json.loads((base / 'config.json').read_text())
iface = config['interface']
binary = Path.home() / '.local/lib/native-clipboard/ac-dc'
for name in ('identity', 'bonjour', 'ids_identifier'):
    path = Path(config[name])
    if not path.is_absolute() or not path.is_file():
        raise SystemExit(f'Missing configured {name} file')

ble_fields = ('ble_keys', 'peer_signing_fingerprint_file')
ble_enabled = any(name in config for name in ble_fields)
fingerprint = None
if ble_enabled:
    for name in ble_fields:
        path = Path(config.get(name, ''))
        if not path.is_absolute() or not path.is_file():
            raise SystemExit(f'Missing configured {name} file')
    fingerprint = Path(config['peer_signing_fingerprint_file']).read_text().strip()
    if not re.fullmatch(r'[0-9a-fA-F]{64}', fingerprint):
        raise SystemExit('Invalid peer signing fingerprint')

while True:
    try:
        result = subprocess.run(['ip', '-j', '-4', 'address', 'show', 'dev', iface],
                                capture_output=True, timeout=5, check=True)
        addresses = [a['local'] for link in json.loads(result.stdout)
                     for a in link.get('addr_info', []) if a.get('scope') == 'global']
        address = next((a for a in addresses if not ipaddress.ip_address(a).is_loopback), None)
    except (OSError, subprocess.SubprocessError, ValueError):
        address = None
    if address:
        break
    time.sleep(5)

args = [str(binary), 'ble-listen-probe' if ble_enabled else 'listen-probe',
        '--continuous', '--bind', address,
        '--iface', iface, '--port', '51515', '--identity', config['identity'],
        '--txt', config['bonjour'],
        '--system-info-ids-id-file', config['ids_identifier'],
        '--copy-verified-text']
if ble_enabled:
    args += ['--keys', config['ble_keys'], '--peer-signing-fingerprint', fingerprint]
else:
    args += ['--observe-system-info', '--probe-pasteboard-types',
             '--system-info-readiness-barrier', '--probe-pasteboard-data']
os.execv(binary, args)
