"""Check tracked publication candidates without printing suspected secrets."""
from __future__ import annotations

from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
SKIP = {'.git', '.venv', 'venv', '__pycache__', 'build', 'dist'}
BLOCKED_SUFFIXES = {'.db', '.sqlite', '.sqlite3', '.key', '.pem', '.pfx', '.log', '.exe', '.bin'}
ALLOWED_SUFFIXES = {'.py', '.js', '.css', '.html', '.md', '.txt', '.yml', '.yaml', '.toml'}
ALLOWED_NAMES = {'LICENSE', '.gitignore', '.gitattributes'}
PATTERNS = {
    'private-key': re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----'),
    'github-token': re.compile(r'\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,})\b'),
    'embedded-key-bundle': re.compile(r'WCKEY1:[A-Za-z0-9+/=_-]{80,}'),
    'personal-user-path': re.compile(r'[A-Za-z]:[\\/]+Users[\\/]+(?!Public\b|example\b)[^\s\\/]+', re.I),
    'contact-feature': re.compile(r'embedded_contact|author_contact|contact_resource|data-open-contact|showStartupContact|contactDialog|authorContact'),
    'email': re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b'),
}


def candidates() -> list[Path]:
    if (ROOT / '.git').is_dir():
        result = subprocess.run(['git', '-C', str(ROOT), 'ls-files', '-z', '--cached', '--others', '--exclude-standard'], capture_output=True, check=True)
        return sorted({ROOT / name.decode('utf-8') for name in result.stdout.split(b'\0') if name})
    return sorted(path for path in ROOT.rglob('*') if path.is_file() and not SKIP.intersection(path.relative_to(ROOT).parts))


def main() -> int:
    findings = []
    files = candidates()
    own_path = Path(__file__).resolve()
    # Full third-party license texts can legitimately contain upstream emails.
    exemptions = {'email'}
    for path in files:
        relative = path.relative_to(ROOT)
        if not path.is_file():
            continue
        if path.suffix.lower() in BLOCKED_SUFFIXES or '.db-' in path.name or path.name.startswith('.env'):
            findings.append((str(relative), 'runtime-or-private-file'))
            continue
        if path.suffix.lower() not in ALLOWED_SUFFIXES and path.name not in ALLOWED_NAMES:
            findings.append((str(relative), 'unexpected-file-type'))
            continue
        if path.resolve() == own_path:
            continue
        content = path.read_text(encoding='utf-8-sig')
        for label, pattern in PATTERNS.items():
            if label == 'contact-feature' and relative.parts[0] == 'tests':
                continue
            if label in exemptions and (relative.parts[0] == 'licenses' or relative.as_posix() == 'static/third-party.html'):
                continue
            if pattern.search(content):
                findings.append((str(relative), label))
    if findings:
        for filename, reason in findings:
            print(f'FAIL {filename}: {reason}')
        return 1
    print(f'Publication scan passed: {len(files)} source files; no runtime/private candidates found.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
