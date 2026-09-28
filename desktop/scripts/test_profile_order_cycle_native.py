#!/usr/bin/env python3
"""Run the pinned manual profile-order acceptance queue, stopping at first failure.

Each child keeps its own fixture, process, namespace and source guards. This
runner additionally freezes their Python dependencies across the whole queue.
Use --suite for an explicit remaining subset in a new artifact directory; a
failed attempt is never overwritten or silently retried.
"""
import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time


DESKTOP = Path(__file__).resolve().parents[1]
SUITES = (
    ('order', 'test_profile_order_native.py', 'profile_order_ui.py', 32, False),
    ('library', 'test_profile_order_native.py', 'library_ui.py', 14, False),
    ('dropdown', 'test_profile_order_native.py', 'dropdown_ui.py', 34, False),
    ('group-drag', 'test_profile_order_native.py', 'group_drag_ui.py', 17, False),
    ('bulk', 'test_profile_order_native.py', 'bulk_ui.py', 14, False),
    ('groups', 'test_profile_order_native.py', 'grouped_library_ui.py', 33, False),
    ('vpn-probes', 'test_vpn_probes_native.py', 'vpn_probes_ui.py', 27, False),
)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_json(path, value):
    # Preserve the previous complete progress record if the process is stopped
    # during serialization; all stage artifacts remain in their own directories.
    temporary = path.with_suffix(path.suffix + '.tmp')
    temporary.write_text(json.dumps(value, indent=2) + '\n')
    temporary.replace(path)


def source_files():
    seeds = {Path(__file__).resolve()}
    for _, wrapper, module, _, _ in SUITES:
        seeds.add(DESKTOP / 'scripts' / wrapper)
        seeds.add(DESKTOP / 'tests' / module)
    # The dispatch files contain many unrelated optional suites. Freeze the
    # dispatch itself and explicitly seed the shared helpers used by this queue.
    dispatch = {DESKTOP / 'scripts/test_native.py', DESKTOP / 'tests/native_smoke.py'}
    seeds.update(dispatch)
    seeds.update(DESKTOP / 'tests' / name for name in (
        'native_transport.py', 'native_menu.py', 'native_processes.py', 'profile_order_input.py',
        'native_screenshot.py', 'native_dialogs.py', 'rfd_dialog_fixture.py',
        'window_ui.py', 'tray_ui.py', 'vpn_auth_fixture.py',
        'vpn_otp_fixture.py', 'vpn_credentials_fixture.py', 'vpn_probe_fixture36.py', 'external_core_fixture.py'))
    pending, found = list(seeds), set()
    while pending:
        path = pending.pop()
        if path in found:
            continue
        assert path.is_file(), 'Missing queue source: ' + str(path)
        found.add(path)
        if path in dispatch or path.suffix != '.py':
            continue
        for node in ast.walk(ast.parse(path.read_text())):
            modules = []
            if isinstance(node, ast.ImportFrom) and node.module:
                modules.append(node.module)
            elif isinstance(node, ast.Import):
                modules.extend(alias.name for alias in node.names)
            for module in modules:
                for folder in ['tests', 'scripts']:
                    candidate = DESKTOP / folder / (module.replace('.', '/') + '.py')
                    if candidate.is_file():
                        pending.append(candidate)
    return sorted(found)


def validate_stage(directory, expected, managed, app_sha, core_sha):
    native = directory / 'fixture-native' if managed else directory
    evidence = [directory / 'summary.json', native / 'results.json']
    if managed:
        evidence.extend([native / 'summary.json', directory / 'namespace-cleanup.json'])
    evidence = sorted(set(evidence))
    summaries = [directory / 'summary.json'] + ([native / 'summary.json'] if managed else [])
    for path in summaries:
        value = json.loads(path.read_text())
        assert value.get('passed') is True, 'Child did not report successful acceptance'
        assert value['applicationSha256'] == app_sha and value['coreSha256'] == core_sha, 'Child pin mismatch'
        assert value.get('pinnedInputsUnchanged') is True, 'Child pin guard did not pass'
        for key in ['testSourcesUnchanged', 'sourcesUnchanged', 'hostNetworkUnchanged', 'hostResolvConfUnchanged']:
            if key in value:
                assert value[key] is True, 'Child guard failed: ' + key
    result = json.loads((native / 'results.json').read_text())
    assert result['count'] == len(result['checks']) == expected, 'Unexpected completed assertion count'
    assert json.loads((native / 'summary.json').read_text())['checks'] == expected
    if managed:
        assert json.loads((directory / 'namespace-cleanup.json').read_text())['baselineRestored'] is True
        outer = json.loads((directory / 'summary.json').read_text())
        assert all(outer.get(key) is True for key in ['hostNetworkUnchanged', 'hostResolvConfUnchanged', 'sourcesUnchanged'])
    return [{'path': str(path.relative_to(directory)), 'sha256': sha(path)} for path in evidence]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--application', type=Path, required=True)
    parser.add_argument('--application-sha256', required=True)
    parser.add_argument('--core-sha256', required=True)
    parser.add_argument('--artifacts', type=Path, required=True)
    parser.add_argument('--suite', action='append', choices=[row[0] for row in SUITES],
                        help='Explicit subset in canonical order; each attempt needs a new artifact directory')
    parser.add_argument('--plan-only', action='store_true', help='Hash and freeze the queue without opening an app or starting a fixture')
    args = parser.parse_args()
    assert not os.environ.get('_THRONIUM_OTP_LAYOUT_DIAGNOSTIC'), 'Diagnostic style injection cannot run in an acceptance queue'
    requested = args.suite or [row[0] for row in SUITES]
    assert len(requested) == len(set(requested)), 'Duplicate suite selection'
    selected = [row for row in SUITES if row[0] in requested]
    app, out = args.application.resolve(), args.artifacts.resolve()
    core = app.with_name('ThroniumCore')
    assert sha(app) == args.application_sha256 and sha(core) == args.core_sha256, 'Pinned input mismatch'
    files = source_files()
    before = {str(path.relative_to(DESKTOP)): sha(path) for path in files}
    out.mkdir(parents=True, exist_ok=False)
    for path in files:
        target = out / 'queue-sources' / path.relative_to(DESKTOP)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, target)
    started = time.monotonic()
    state = {'passed': False, 'planOnly': args.plan_only, 'completeAcceptanceQueue': len(selected) == len(SUITES),
             'applicationSha256': args.application_sha256, 'coreSha256': args.core_sha256,
             'expectedChecks': sum(row[3] for row in selected), 'completedChecks': 0,
             'sourceHashes': before, 'stages': [], 'screenshotReviewComplete': False}
    plan = []
    for index, (name, wrapper, _, expected, managed) in enumerate(selected, 1):
        directory = out / f'{index:02d}-{name}'
        command = [sys.executable, str(DESKTOP / 'scripts' / wrapper), '--application', str(app),
                   '--application-sha256', args.application_sha256, '--core-sha256', args.core_sha256,
                   '--artifacts', str(directory)]
        plan.append({'suite': name, 'expectedChecks': expected, 'managedNamespace': managed,
                     'directory': directory.name, 'command': command + (['--suite', name] if wrapper == 'test_profile_order_native.py' else [])})
    write_json(out / 'queue-plan.json', {**state, 'plan': plan})

    def guards():
        now = {str(path.relative_to(DESKTOP)): sha(path) if path.is_file() else None for path in files}
        state['sourceChanges'] = [name for name in before if before[name] != now[name]]
        state['pinnedInputsUnchanged'] = sha(app) == args.application_sha256 and sha(core) == args.core_sha256
        state['sourcesUnchanged'] = not state['sourceChanges']
        if not state['pinnedInputsUnchanged'] or not state['sourcesUnchanged']:
            state['passed'] = False
            raise AssertionError('Queue input drift')

    try:
        guards()
        if args.plan_only:
            state['planVerified'] = True
            print('PLAN', state['expectedChecks'], 'assertions; no app or fixture started', flush=True)
            return
        for item in plan:
            guards()
            entry = {'suite': item['suite'], 'expectedChecks': item['expectedChecks'],
                     'directory': item['directory'], 'passed': False}
            state['stages'].append(entry)
            write_json(out / 'queue-progress.json', state)
            print('START', item['suite'], 'expected', item['expectedChecks'], flush=True)
            stage_started = time.monotonic()
            with (out / (item['directory'] + '-wrapper.log')).open('w') as log:
                result = subprocess.run(item['command'], stdout=log, stderr=subprocess.STDOUT)
            entry.update(exitCode=result.returncode, seconds=round(time.monotonic() - stage_started, 3))
            directory = out / item['directory']
            native = directory / 'fixture-native' if item['managedNamespace'] else directory
            log_path = native / 'native.log'
            entry['observedPassLines'] = sum(line.startswith('PASS ') for line in log_path.read_text(errors='replace').splitlines()) if log_path.exists() else 0
            guards()
            if result.returncode:
                raise RuntimeError('Native stage failed: ' + item['suite'])
            entry['evidence'] = validate_stage(directory, item['expectedChecks'], item['managedNamespace'],
                                               args.application_sha256, args.core_sha256)
            entry['passed'] = True
            state['completedChecks'] += item['expectedChecks']
            write_json(out / 'queue-progress.json', state)
            print('PASS', item['suite'], item['expectedChecks'], 'queue', state['completedChecks'], flush=True)
        state['passed'] = True
        print('QUEUE PASS', state['completedChecks'], flush=True)
    except BaseException as error:
        state['errorType'] = type(error).__name__
        # Exceptions here contain only local paths or static orchestration errors,
        # never fixture answers or browser payloads.
        state['error'] = str(error)
        raise
    finally:
        state['seconds'] = round(time.monotonic() - started, 3)
        try:
            guards()
        finally:
            name = ('queue-plan-verified.json' if args.plan_only and state.get('planVerified') and state['sourcesUnchanged'] and state['pinnedInputsUnchanged']
                    else ('summary.json' if state['passed'] else 'attempt-status.json'))
            write_json(out / name, state)


if __name__ == '__main__':
    main()
