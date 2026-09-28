"""Observe children spawned by every thread of the disposable native process."""
from pathlib import Path


def core_pids(pid):
    children = set()
    for task in Path('/proc', str(pid), 'task').glob('*/children'):
        try: children.update(task.read_text().split())
        except OSError: pass  # A worker thread may finish while being observed.
    cores = []
    for child in children:
        try:
            if Path('/proc', child, 'comm').read_text().strip() == 'ThroniumCore': cores.append(child)
        except OSError: pass
    return sorted(cores)
