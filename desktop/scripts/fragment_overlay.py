"""Apply the reviewed custom TLS fragmentation fix to the exact pinned fork."""
import hashlib
from pathlib import Path

ORIGINALS = {
    'fragment.go': 'a223ab3ba3398a5589676af30dee239b3155abbb64f8cb2d724f32515c5a5658',
    'default.go': 'e5bf0d2d9849bc49f2ee51b8070a2ccf172943785f9260c2d66ae92a9619563c',
}

def prepare(source: Path, module: Path):
    originals = {}
    for name, expected in ORIGINALS.items():
        data = (source / 'common/dialer' / name).read_bytes()
        if hashlib.sha256(data).hexdigest() != expected:
            raise RuntimeError('Pinned TLS fragmentation changed; review the fragmentation overlay')
        originals[name] = data.decode()
    default = originals['default.go']
    for option, minimum in [('Sleep', 0), ('Size', 1)]:
        old = f'option.Parse2IntRange(options.TLSFragment.{option})'
        if default.count(old) != 1:
            raise RuntimeError('Pinned TLS fragmentation parser changed; review the fragmentation overlay')
        default = default.replace(old, f'parseTLSFragmentRange(options.TLSFragment.{option}, {minimum})')
    replacement = (Path(__file__).parent / 'overlays/sing-box/fragment.go').read_bytes()
    files = []
    for name, data in [('fragment.go', replacement), ('default.go', default.encode())]:
        target = module / 'common/dialer' / name
        target.chmod(0o644)
        target.write_bytes(data)
        files.append(target)
    return files
