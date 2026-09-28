"""Mixed-scope real Qt archives with OTP entries; all entries contain public
RFC keys. The archives and their manifest are committed; the program that made
them from Throne's OTP schema is in git history."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / 'desktop/engine/src/legacy_backup/otp/fixtures'
DIRECTORY = Path(__file__).with_name('fixtures') / 'legacy-otp'
