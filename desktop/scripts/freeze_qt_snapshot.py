#!/usr/bin/env python3
"""Freeze the Qt Throne slices the port's tests read, so they stop reading its tree.

Tests must not depend on the Qt application being checked out: this copies the
exact blocks they assert against into two snapshots and records where each came
from, with the hash of the block and of its source file.

    freeze_qt_snapshot.py [--throne <checkout of throneproj/Throne>]

Run it only to refresh a snapshot against a newer upstream; the checkout is the
repository root while Qt still lives here, or an upstream clone afterwards.
"""
import argparse
import hashlib
import json
import pathlib
import re
import subprocess

DESKTOP = pathlib.Path(__file__).resolve().parents[1]
ENGINE = DESKTOP / 'engine/qt-source'
TESTS = DESKTOP / 'tests/qt-snapshot'
DDL = re.compile(r'db\.exec\(R"\((.*?)\)"\)', re.S)
MEMBERS = re.compile(r'\{"(\w+)",\s*&(\w+)\}')

# Balanced C++ bodies the engine's tests assert on, verbatim.
BLOCKS = [
    ('settings-repo-init-maps.cpp', 'src/database/SettingsRepo.cpp',
     'void SettingsRepo::initMaps() {'),
    ('generate-warp-profile.cpp', 'src/configs/generate.cpp',
     'std::shared_ptr<Profile> getWarpProfile() {'),
    ('group-updater-refresh.cpp', 'src/configs/sub/GroupUpdater.cpp',
     'void GroupUpdater::refresh(int gid, bool showDiff) {'),
    ('mainwindow-setup-minutes.cpp', 'src/ui/mainWindow/mainwindow_setup.cpp',
     'const auto minutesOf = [](int v)'),
]

# Whole Qt files an oracle was compiled from: the test proves the oracle still
# answers for exactly this code, so the copy must stay byte for byte.
FILES = [
    ('global-otp.cpp', 'src/global/OTP.cpp'),
    ('global-otp.hpp', 'include/global/OTP.hpp'),
]

# SQLite schemas the archive fixtures create their synthetic databases with.
SCHEMAS = ['GroupsRepo', 'ProfilesRepo', 'OtpProfilesRepo', 'RoutesRepo', 'SettingsRepo']


def sha(data):
    return hashlib.sha256(data if isinstance(data, bytes) else data.encode()).hexdigest()


def block(text, marker):
    """Extract a balanced body, skipping comments and string literals."""
    start = text.index(marker)
    i = text.index('{', start)
    depth = 0
    while i < len(text):
        if text.startswith('//', i):
            i = text.index('\n', i)
            continue
        if text.startswith('/*', i):
            i = text.index('*/', i + 2) + 2
            continue
        if text.startswith('R"', i):
            middle = text.index('(', i + 2)
            delimiter = text[i + 2:middle]
            i = text.index(')' + delimiter + '"', middle) + len(delimiter) + 2
            continue
        if text[i] in '"\'':
            quote = text[i]
            i += 1
            while i < len(text):
                if text[i] == '\\':
                    i += 2
                    continue
                if text[i] == quote:
                    i += 1
                    break
                i += 1
            continue
        if text[i] == '{':
            depth += 1
        elif text[i] == '}':
            depth -= 1
            if depth == 0:
                return text[start:i + 1], text[:start].count('\n') + 1
        i += 1
    raise SystemExit(f'unbalanced source for {marker}')


def upstream(throne):
    try:
        commit = subprocess.check_output(
            ['git', '-C', str(throne), 'rev-parse', 'HEAD'], text=True).strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        commit = None
    return {'repository': 'throneproj/Throne', 'commit': commit}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--throne', type=pathlib.Path, default=DESKTOP.parent,
                        help='checkout that still carries the Qt application')
    args = parser.parse_args()
    throne = args.throne.resolve()
    ENGINE.mkdir(parents=True, exist_ok=True)
    TESTS.mkdir(parents=True, exist_ok=True)

    extracts = []
    for name, path, marker in BLOCKS:
        source = (throne / path).read_text()
        body, line = block(source, marker)
        (ENGINE / name).write_text(body + '\n')
        extracts.append({'file': name, 'path': path, 'marker': marker, 'line': line,
                         'sha256': sha(body + '\n'), 'sourceSha256': sha(source)})
    for name, path in FILES:
        source = (throne / path).read_bytes()
        (ENGINE / name).write_bytes(source)
        extracts.append({'file': name, 'path': path, 'verbatim': True,
                         'sha256': sha(source), 'sourceSha256': sha(source)})
    (ENGINE / 'manifest.json').write_text(json.dumps({
        'description': 'Qt Throne blocks and whole files the engine tests assert on. '
                       'Refresh with desktop/scripts/freeze_qt_snapshot.py.',
        'upstream': upstream(throne),
        'extracts': extracts,
    }, indent=2) + '\n')

    schemas = []
    for repo in SCHEMAS:
        source = (throne / 'src/database' / (repo + '.cpp')).read_text()
        statements = DDL.findall(source)
        if not statements:
            raise SystemExit(f'no DDL found in {repo}')
        name = f'{repo}.ddl.json'
        body = json.dumps(statements, indent=2) + '\n'
        (TESTS / name).write_text(body)
        schemas.append({'file': name, 'path': f'src/database/{repo}.cpp',
                        'blocks': len(statements), 'sha256': sha(body),
                        'sourceSha256': sha(source)})
        if repo == 'SettingsRepo':
            keys = dict(MEMBERS.findall(source))
            members = json.dumps(keys, indent=2, sort_keys=True) + '\n'
            (TESTS / 'SettingsRepo.members.json').write_text(members)
            schemas.append({'file': 'SettingsRepo.members.json',
                            'path': 'src/database/SettingsRepo.cpp',
                            'entries': len(keys), 'sha256': sha(members),
                            'sourceSha256': sha(source)})
    (TESTS / 'manifest.json').write_text(json.dumps({
        'description': 'Qt Throne SQLite schemas and stored-key map the archive '
                       'fixtures build synthetic databases with. '
                       'Refresh with desktop/scripts/freeze_qt_snapshot.py.',
        'upstream': upstream(throne),
        'extracts': schemas,
    }, indent=2) + '\n')
    print(f'frozen {len(extracts)} blocks and files -> {ENGINE}')
    print(f'frozen {len(schemas)} schemas -> {TESTS}')


if __name__ == '__main__':
    main()
