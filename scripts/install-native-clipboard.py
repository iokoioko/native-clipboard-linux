#!/usr/bin/python
"""Install experimental direct text sync from prepared bootstrap files. Existing config is preserved."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess

repo = Path(__file__).resolve().parent.parent
home = Path.home()
app = home / '.local/lib/native-clipboard'
config_dir = home / '.config/native-clipboard'
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--config', type=Path, help='Existing bootstrap configuration JSON (required on first install)')
parser.add_argument('--binary', type=Path, default=repo / 'target/debug/ac-dc')
parser.add_argument('--no-tray', action='store_true', help='Skip tray login autostart (no PySide6 needed)')
args = parser.parse_args()
config_path = config_dir / 'config.json'
source_config = config_path if config_path.exists() else (args.config or config_path)
if not source_config.is_file():
    parser.error('Supply --config with your independently prepared bootstrap configuration; see README.md')
config = json.loads(source_config.read_text())
if not isinstance(config.get('interface'), str) or not config['interface']:
    parser.error('config needs a network interface')
for key in ('identity', 'bonjour', 'ids_identifier'):
    path = Path(config[key])
    if not path.is_absolute() or not path.is_file():
        parser.error(f'Missing absolute bootstrap file path: {key}')
if not args.binary.is_file():
    parser.error('Build first or supply --binary')
app.mkdir(parents=True, exist_ok=True)
config_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
if not config_path.exists():
    with config_path.open('x') as f:
        os.chmod(config_path, 0o600)
        json.dump(config, f, indent=2)
        f.write('\n')
for source, name in [(args.binary, 'ac-dc'),
                     (repo / 'scripts/native-clipboard-run.py', 'native-clipboard-run.py'),
                     (repo / 'scripts/native-clipboard-tray.py', 'native-clipboard-tray.py')]:
    target = app / name
    temp = app / (name + '.new')
    shutil.copyfile(source, temp)
    temp.chmod(0o755)
    temp.replace(target)
bin_dir = home / '.local/bin'
bin_dir.mkdir(parents=True, exist_ok=True)
shutil.copyfile(repo / 'scripts/native-clipboard', bin_dir / 'native-clipboard')
(bin_dir / 'native-clipboard').chmod(0o755)
units = home / '.config/systemd/user'
units.mkdir(parents=True, exist_ok=True)
shutil.copyfile(repo / 'scripts/native-clipboard.service', units / 'native-clipboard.service')
if not args.no_tray:
    autostart = home / '.config/autostart'
    autostart.mkdir(parents=True, exist_ok=True)
    (autostart / 'native-clipboard-tray.desktop').write_text(
        '[Desktop Entry]\nType=Application\nName=Native Clipboard\n'
        'Comment=Direct iPhone clipboard sync status and pause control\n'
        f'Exec=/usr/bin/python "{app / "native-clipboard-tray.py"}"\n'
        'Icon=edit-paste\nTerminal=false\n')
subprocess.run(['systemd-analyze', '--user', 'verify', str(units / 'native-clipboard.service')], check=True)
subprocess.run(['systemctl', '--user', 'daemon-reload'], check=True)
print('Installed. Enable/start with: systemctl --user enable --now native-clipboard.service')
