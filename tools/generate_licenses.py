"""Create an offline notice page from project and installed dependency licenses."""
from __future__ import annotations

import html
import importlib.metadata as metadata
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]


def generate(include_build: bool = False) -> Path:
    sections = []
    for name in ('LICENSE', 'THIRD_PARTY_NOTICES.md'):
        sections.append((name, (ROOT / name).read_text(encoding='utf-8')))
    for path in sorted((ROOT / 'licenses').glob('*.txt')):
        sections.append((path.name, path.read_text(encoding='utf-8')))
    names = ['sqlcipher3', 'zstandard']
    if include_build:
        names.append('pyinstaller')
    for name in names:
        distribution = metadata.distribution(name)
        found = []
        for relative in distribution.files or []:
            if any(term in Path(str(relative)).name.lower() for term in ('license', 'copying', 'notice')):
                path = distribution.locate_file(relative)
                if path.is_file():
                    found.append(path)
        if not found:
            raise RuntimeError(f'License not found in installed distribution: {name}')
        for path in found:
            sections.append((f'{name} {distribution.version}: {path.name}', path.read_text(encoding='utf-8', errors='replace')))
    python_license = Path(sys.base_prefix) / 'LICENSE.txt'
    if not python_license.is_file():
        python_license = Path(sys.base_prefix) / 'LICENSE'
    if not python_license.is_file():
        raise RuntimeError('Python runtime license not found')
    sections.append(('Python runtime', python_license.read_text(encoding='utf-8', errors='replace')))
    body = '\n'.join(f'<h2>{html.escape(title)}</h2><pre>{html.escape(text)}</pre>' for title, text in sections)
    output = ROOT / 'static/third-party.html'
    output.write_text('''<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><title>第三方组件与许可</title>
<style>body{font:15px/1.65 sans-serif;max-width:960px;margin:36px auto;padding:0 24px}pre{white-space:pre-wrap;overflow-wrap:anywhere}h2{margin-top:32px}</style>
</head><body><h1>第三方组件与许可</h1><p>本页随源码或程序离线分发。</p>
''' + body + '\n</body></html>\n', encoding='utf-8', newline='\n')
    return output


if __name__ == '__main__':
    print(generate('--include-build' in sys.argv).relative_to(ROOT))
