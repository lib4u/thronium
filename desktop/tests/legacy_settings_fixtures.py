"""Mixed profile/settings archives encoded by the actual Qt6 writer. The
archives and their manifest are committed; the program that made them from
Throne's settings schema is in git history."""
from pathlib import Path

SOURCE = Path(__file__).resolve().parents[1] / 'engine/src/legacy_backup/settings/fixtures'
DIRECTORY = Path(__file__).with_name('fixtures') / 'legacy-settings'
