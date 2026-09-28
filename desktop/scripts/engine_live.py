#!/usr/bin/env python3
"""Run the engine's live tests: the `#[ignore]` ones that need the real core.

    npm run test:engine-live
    npm run test:engine-live -- --list
    npm run test:engine-live -- vpn_otp_live connection::tests::

They run with the built core (`npm run core:build`), each in its own process,
on loopback, synthetic fixtures from `tests/` and private namespaces only —
never the host's network settings. The core accepts only a parent named
Thronium beside it, so a test binary runs as `Thronium` next to a copy of
`ThroniumCore`. Every ignored test must be listed below; an unlisted one fails
the run, so a new live test cannot go unrun. The desktop key-store test reaches
this desktop's real keyring and runs only with --with-keyring.

Results: `test-results/engine-live/<time>/<test>.log` and `summary.json`.
"""
import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

DESKTOP = Path(__file__).resolve().parents[1]
ENGINE = DESKTOP / 'engine/Cargo.toml'
TESTS = DESKTOP / 'tests'
KEYRING = 'secrets::keyring::tests::the_desktop_store_keeps_one_key_and_returns_it_again'

# Integration test targets: how each is run. `env` values may name
# {core}, {python}, {work} and {tests}.
TARGETS = {
    'nested_routing_oracle': {},
    'inline_ruleset_oracle': {},
    'local_recovery_review': {},
    'profile_order_live': {},
    'ws_early_data_public': {},
    'vpn_credentials_live': {'env': {'THRONIUM_CREDENTIALS_FIXTURE': '{tests}/vpn_credentials_fixture.py'}},
    'vpn_otp_live': {'env': {'THRONIUM_TEST_OTP_FIXTURE': '{tests}/vpn_otp_fixture.py'}},
    # GNOME's proxy settings in a private keyfile, on a private session bus.
    'vpn_probes_live': {'bus': True, 'config': 'thronium-vpn-probes36-', 'env': {
        'XDG_CURRENT_DESKTOP': 'GNOME', 'THRONIUM_PROBE_FIXTURE': '{tests}/vpn_probe_fixture36.py',
        'THRONIUM_PROBE_PYTHON': '{python}'}},
    'vpn_policy_live': {'bus': True, 'config': 'thronium-policy34-', 'env': {
        'THRONIUM_POLICY_FIXTURE': '{tests}/vpn_policy_fixture34.py', 'THRONIUM_POLICY_PYTHON': '{python}'}},
    # These bring up their own fixtures and sandboxes through a runner.
    'profile_tls_review': {'runner': ['{tests}/profile_tls_review.py', '--pinned']},
    'system_proxy_recovery_review': {'runner': ['{tests}/system_proxy_recovery_review.py', '--pinned']},
    'vpn_auth_public': {'runner': ['{tests}/vpn_auth_public.py', '--pinned']},
    'vpn_credentials_managed_live': {'runner': ['{tests}/vpn_credentials_managed_public.py', '--test-binary',
                                                '--fixture', '{tests}/vpn_credentials_fixture.py']},
}


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def binaries():
    """Test binaries of the engine by target name ('lib' for the library)."""
    lines = subprocess.run(['cargo', 'test', '--locked', '--manifest-path', str(ENGINE), '--no-run',
                            '--message-format=json'], capture_output=True, text=True, check=True).stdout
    found = {}
    for line in lines.splitlines():
        try:
            message = json.loads(line)
        except ValueError:
            continue
        if message.get('executable') and message.get('profile', {}).get('test'):
            target = message['target']
            found['lib' if 'lib' in target['kind'] else target['name']] = Path(message['executable'])
    return found


def ignored(binary):
    listed = subprocess.run([str(binary), '--ignored', '--list', '--format', 'terse'],
                            capture_output=True, text=True, check=True).stdout
    return [line.removesuffix(': test') for line in listed.splitlines() if line.endswith(': test')]


def default_core():
    host = next(line.removeprefix('host: ') for line in subprocess.check_output(
        ['rustc', '-vV'], text=True).splitlines() if line.startswith('host: '))
    return DESKTOP / 'src-tauri/binaries' / f'ThroniumCore-{host}'


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('only', nargs='*', help='targets or test-name prefixes to run')
    parser.add_argument('--core', type=Path)
    parser.add_argument('--list', action='store_true')
    parser.add_argument('--with-keyring', action='store_true')
    parser.add_argument('--timeout', type=int, default=900)
    args = parser.parse_args()
    core = (args.core or default_core()).resolve()
    if not core.is_file():
        parser.error(f'{core} is missing; run npm run core:build')
    built = binaries()
    library = [name for name in ignored(built['lib']) if args.with_keyring or name != KEYRING]
    unlisted = [target for target, binary in built.items()
                if target != 'lib' and target not in TARGETS and ignored(binary)]
    if unlisted:
        sys.exit('live tests without a way to run them here: ' + ', '.join(unlisted))
    plan = [('lib', name) for name in library] + [(target, None) for target in TARGETS]
    if args.only:
        plan = [(t, n) for t, n in plan if any((n or t).startswith(o) or t == o for o in args.only)]
    if args.list:
        for target, name in plan:
            print(name or target)
        return 0
    root = DESKTOP / 'test-results/engine-live' / time.strftime('%Y%m%d-%H%M%S')
    root.mkdir(parents=True)
    python = str(Path(shutil.which('python3')).resolve())
    results = []
    for target, name in plan:
        label = name or target
        work = root / re.sub(r'[^\w.-]', '_', label)
        work.mkdir()
        spec = TARGETS.get(target, {})
        fill = lambda text: text.format(core=work / 'ThroniumCore', python=python, work=work, tests=TESTS)
        env = {**os.environ, 'THRONIUM_TEST_CORE': str(work / 'ThroniumCore'),
               **{key: fill(value) for key, value in spec.get('env', {}).items()}}
        if 'runner' in spec:
            runner = [fill(part) for part in spec['runner']]
            pin = work / 'pin.json'
            pin.write_text('{}\n')
            command = [sys.executable, runner[0], '--core', str(core), '--core-sha256', sha(core),
                       '--artifacts', str(work / 'artifacts')]
            for option in runner[1:]:
                if option == '--pinned':
                    command += ['--build-inputs', str(pin)]
                elif option == '--test-binary':
                    command += ['--test-binary', str(built[target])]
                else:
                    command.append(option)
        else:
            shutil.copy2(core, work / 'ThroniumCore')
            shutil.copy2(built[target], work / 'Thronium')
            command = [str(work / 'Thronium'), '--ignored', '--test-threads=1']
            command += ['--exact', name] if name else []
            if 'config' in spec:
                config = work / (spec['config'] + 'config')
                config.mkdir()
                env.update(GSETTINGS_BACKEND='keyfile', XDG_CONFIG_HOME=str(config))
            if spec.get('bus'):
                command = ['dbus-run-session', '--'] + command
        started = time.monotonic()
        with (root / f'{work.name}.log').open('w') as log:
            try:
                code = subprocess.run(command, cwd=work, env=env, stdout=log, stderr=subprocess.STDOUT,
                                      timeout=args.timeout).returncode
            except subprocess.TimeoutExpired:
                code = 'timeout'
        result = {'test': label, 'exitCode': code, 'seconds': round(time.monotonic() - started, 1)}
        results.append(result)
        print(json.dumps(result), flush=True)
    (root / 'summary.json').write_text(json.dumps(results, indent=2) + '\n')
    failed = [r['test'] for r in results if r['exitCode'] != 0]
    print(f'{len(results) - len(failed)} passed, {len(failed)} failed' + (': ' + ', '.join(failed) if failed else ''))
    return 1 if failed else 0


if __name__ == '__main__':
    sys.exit(main())
