"""Build a Windows executable and verify its bundled runtime."""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import subprocess
import sys

from generate_licenses import generate

ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mode', choices=['direct', 'copy'], default='direct')
    args = parser.parse_args()
    if os.name != 'nt':
        parser.error('Windows x64 is required')
    generate(include_build=True)
    name = 'WeChatDBEditor' if args.mode == 'direct' else 'WeChatDBCopyEditor'
    entry = 'direct_app.py' if args.mode == 'direct' else 'app.py'
    subprocess.run([
        sys.executable, '-m', 'PyInstaller', '--noconfirm', '--clean',
        '--onefile', '--windowed', '--noupx', '--name', name,
        '--specpath', 'build', '--add-data', f'{ROOT / "static"};static',
        '--collect-all', 'sqlcipher3', '--collect-all', 'zstandard', entry,
    ], cwd=ROOT, check=True)
    executable = ROOT / 'dist' / f'{name}.exe'
    subprocess.run([str(executable), '--self-test'], cwd=ROOT, check=True, timeout=120)
    print(f'Built and verified: {executable.relative_to(ROOT)}')


if __name__ == '__main__':
    main()
