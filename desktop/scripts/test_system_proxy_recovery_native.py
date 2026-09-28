#!/usr/bin/env python3
"""Run private GNOME proxy recovery against verified disposable binary copies."""
from pathlib import Path
import runpy
import sys

sys.argv.extend(['--suite','system-proxy'])
runpy.run_path(str(Path(__file__).with_name('test_core_recovery_native.py')),run_name='__main__')
