#!/usr/bin/env python3
"""Throne's `.thrbackup` container, written the way Qt-Throne writes it.

Byte for byte what Qt 6 produces for `QDataStream` (`Qt_6_0`, little endian):
`THRN`, a quint32 version, the metadata `QString` and a
`QMap<QString, QByteArray>` of files. It replaces the Qt-built golden writer
the stands used to call; `python3 thrbackup_writer.py --verify <archive>...`
proves the equivalence on archives the real Qt writer made.

As a program it keeps that writer's interface: `thrbackup_writer.py <folder>
<database.sqlite>` writes the same set of archives into the folder (parts
masks 0–31 and the edge cases) and prints what wrote them.
"""
import json
import pathlib
import struct
import sys

WRITER = 'thrbackup_writer.py (QDataStream Qt_6_0, little endian)'
NULL = 0xFFFFFFFF


def _string(value):
    """A QString; None is the null string."""
    if value is None:
        return struct.pack('<I', NULL)
    # Lone surrogates must survive, as QString keeps them.
    data = value.encode('utf-16-le', 'surrogatepass')
    return struct.pack('<I', len(data)) + data


def _bytes(value):
    """A QByteArray; None is the null array."""
    if value is None:
        return struct.pack('<I', NULL)
    return struct.pack('<I', len(value)) + value


def _utf16_key(name):
    # QMap<QString> orders by UTF-16 code units, not by code points.
    return name.encode('utf-16-be', 'surrogatepass')


def encode(version, metadata, files):
    """The archive bytes. files maps names to bytes (None for a null array)."""
    out = [b'THRN', struct.pack('<I', version), _string(metadata), struct.pack('<I', len(files))]
    for name in sorted(files, key=_utf16_key):
        out += [_string(name), _bytes(files[name])]
    return b''.join(out)


def decode(data):
    """version, metadata, files (in stream order) of an archive."""
    if data[:4] != b'THRN':
        raise ValueError('not a thrbackup archive')
    offset = 4

    def number():
        nonlocal offset
        value = struct.unpack_from('<I', data, offset)[0]
        offset += 4
        return value

    def chunk(text):
        nonlocal offset
        size = number()
        if size == NULL:
            return None
        value = data[offset:offset + size]
        offset += size
        return value.decode('utf-16-le', 'surrogatepass') if text else value

    version = number()
    metadata = chunk(True)
    files = {}
    for _ in range(number()):
        name = chunk(True)
        files[name] = chunk(False)
    if offset != len(data):
        raise ValueError('trailing bytes')
    return version, metadata, files


def qt_json(value):
    """QJsonDocument::toJson(Compact): sorted keys, raw UTF-8, no spaces."""
    return json.dumps(value, ensure_ascii=False, separators=(',', ':'), sort_keys=True)


def write_set(folder, database):
    """The archive set the Qt golden writer made from one SQLite file."""
    folder = pathlib.Path(folder)
    base = {'backup_version': 2, 'created_at': 'Fri Sep 11 12:00:00 2026 🦊',
            'platform': 'fixture', 'future_metadata': {'keep': 'metadata-secret-fixture'}}

    def put(name, version, metadata, files):
        (folder / name).write_bytes(encode(version, metadata, files))

    for mask in range(32):
        metadata = dict(base, parts={'profiles': bool(mask & 1), 'routes': bool(mask & 2),
                                     'settings': bool(mask & 4), 'otp': bool(mask & 8),
                                     'icons': bool(mask & 16)})
        files = {}
        if mask & 15:
            files['database'] = database
        if mask & 16:
            files['icons/日本 🦊.png'] = bytes.fromhex('89504e4700010203ff')
            files['icons/../../never-extract-fixture'] = b'fixture'
        files['future/null'] = None
        files['future/empty'] = b''
        put(f'parts-{mask:02d}.thrbackup', 2, qt_json(metadata), files)
    files = {'database': database, 'icons/legacy.png': b'icon'}
    put('v1.thrbackup', 1, qt_json(dict(base, backup_version=1)), files)
    put('v2-no-parts.thrbackup', 2, qt_json(base), files)
    put('null-metadata.thrbackup', 2, None, files)
    put('empty-metadata.thrbackup', 2, '', files)
    put('null-database.thrbackup', 2, '{}', dict(files, database=None))
    put('empty-database.thrbackup', 2, '{}', dict(files, database=b''))
    put('invalid-utf16.thrbackup', 2, '{}', {'\ud800': b'invalid Unicode key'})


def verify(paths):
    """Re-encodes each archive; any difference means this writer is wrong."""
    for path in paths:
        data = pathlib.Path(path).read_bytes()
        version, metadata, files = decode(data)
        if encode(version, metadata, files) != data:
            raise SystemExit(f'differs from Qt: {path}')
        # The metadata text is what QJsonDocument wrote for its object.
        if metadata and metadata.startswith('{') and qt_json(json.loads(metadata)) != metadata:
            raise SystemExit(f'metadata differs from Qt: {path}')
    print(f'{len(paths)} archives identical')


def main(argv):
    if argv[1:2] == ['--verify']:
        verify(argv[2:])
        return 0
    if len(argv) != 3:
        print(__doc__, file=sys.stderr)
        return 2
    write_set(argv[1], pathlib.Path(argv[2]).read_bytes())
    print(WRITER)
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
