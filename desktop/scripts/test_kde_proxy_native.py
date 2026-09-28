#!/usr/bin/env python3
"""Private KDE settings, libproxy traffic and crash recovery on pinned App/Core copies."""
from pathlib import Path
import runpy
import sys

sys.argv.extend(['--suite', 'kde'])
runpy.run_path(str(Path(__file__).with_name('test_core_recovery_native.py')), run_name='__main__')
