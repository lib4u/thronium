# Independent Qt fixtures

These files contain synthetic data only. No user's backup, subscription, key or
network endpoint was used. Names containing `secret` are deliberately fake test
markers, used to verify that inventory responses do not expose source values.

`../golden_writer.cpp` uses actual Qt `QDataStream` operators with
`QDataStream::Qt_6_0`, little endian, and `QMap<QString, QByteArray>`; the Rust
reader does not generate these compatibility fixtures. The writer prints the
loaded Qt runtime's `qVersion()`. `../make_golden.py` creates a synthetic SQLite
source, invokes that binary, verifies its runtime version and records SHA-256
hashes in `manifest.json`.

The checked-in generation used Qt **6.11.2** from Fedora's official
`qt6-qtbase`, `qt6-qtbase-common` and `qt6-qtbase-devel` RPMs, extracted under an
isolated `/tmp/thronium-legacy-qt-*/sdk`. No system package was installed or
upgraded. SQLite test data was generated with Python's standard `sqlite3`.

To regenerate using a Qt development installation:

```sh
c++ -std=c++17 -fPIC $(pkg-config --cflags Qt6Core) \
  desktop/engine/src/legacy_backup/golden_writer.cpp \
  $(pkg-config --libs Qt6Core) -o /tmp/thronium-golden-writer
python3 desktop/engine/src/legacy_backup/make_golden.py \
  /tmp/thronium-golden-writer 6.11.2
```

For an extracted SDK, replace pkg-config with its Qt include directories,
`-L<SDK>/usr/lib64 -Wl,-rpath,<SDK>/usr/lib64 -lQt6Core`. Neither tool reads
outside its explicit synthetic database/output paths.

The 39 archives cover:

- All 32 masks of profiles/routes/settings/OTP/icons. The embedded database
  intentionally retains rows from unselected parts to verify that `Parts` flags
  determine import availability independently of table presence.
- Container v1 and v2 without `parts`: profiles/routes/settings are available,
  OTP remains unselected even though its table has a row.
- Unicode BMP and supplementary characters; distinct null and empty byte arrays;
  unknown map entries; icon names that look like paths but are never extracted.
- Minimal older mandatory columns, unknown columns, opaque BLOBs, quoted SQL
  identifiers, a view containing a never-executed extension call, and a trigger.
- Nullable and empty mandatory fields, invalid UTF-16, and invalid database arrays.

These goldens verify the reader. They deliberately include unsupported future
profile fields; they do not assert that every profile is convertible/importable.
The native additive-import acceptance fixtures are maintained separately under
`desktop/tests/fixtures`.

References: [Qt stream format](https://doc.qt.io/qt-6/datastreamformat.html),
[QDataStream versioning](https://doc.qt.io/qt-6/qdatastream.html), and the local
Throne writer in `src/ui/setting/dialog_basic_settings.cpp`.
