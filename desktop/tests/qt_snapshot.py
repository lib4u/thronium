#!/usr/bin/env python3
"""Frozen Qt Throne schemas for the import fixtures.

The archive fixtures build synthetic Qt databases from the original
application's own DDL. They read it here — `desktop/tests/qt-snapshot`, whose
manifest records the file each block came from and its hash — never from a Qt
checkout. Refresh with `desktop/scripts/freeze_qt_snapshot.py`.
"""
import hashlib
import json
import pathlib

HERE = pathlib.Path(__file__).resolve().parent / 'qt-snapshot'
MANIFEST = json.loads((HERE / 'manifest.json').read_text())


def _entry(name):
    for extract in MANIFEST['extracts']:
        if extract['file'] == name:
            return extract
    raise AssertionError(f'{name} is not frozen')


def _frozen(name):
    body = (HERE / name).read_text()
    assert hashlib.sha256(body.encode()).hexdigest() == _entry(name)['sha256'], \
        f'{name} no longer matches the recorded Qt block'
    return json.loads(body)


def ddl(repo, count=None):
    """The repository's CREATE statements, in source order."""
    statements = _frozen(f'{repo}.ddl.json')
    if count is None:
        return statements
    assert len(statements) >= count, f'{repo} froze {len(statements)} statements'
    return statements[:count]


def members():
    """Stored SQLite key -> SettingsRepo member name."""
    return _frozen('SettingsRepo.members.json')


def source_sha(repo):
    """Hash of the Qt file the schema was frozen from."""
    return _entry(f'{repo}.ddl.json')['sourceSha256']


def origin(repo):
    """Path of that file inside the Qt application, for fixture manifests."""
    return _entry(f'{repo}.ddl.json')['path']
