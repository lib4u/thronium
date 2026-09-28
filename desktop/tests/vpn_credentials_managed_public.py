#!/usr/bin/env python3
"""Explicit owned-core Engine test in fresh user/network/mount namespaces."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--core', type=Path, required=True)
    parser.add_argument('--core-sha256', required=True)
    parser.add_argument('--test-binary', type=Path, required=True)
    parser.add_argument('--fixture', type=Path, required=True)
    parser.add_argument('--artifacts', type=Path, required=True)
    parser.add_argument('--inside', action='store_true')
    parser.add_argument('--test-name', default='managed_manual_credentials_are_ephemeral_and_frozen_for_openvpn_and_openconnect')
    args = parser.parse_args()
    core, binary, fixture, out = [path.resolve() for path in [args.core, args.test_binary, args.fixture, args.artifacts]]
    assert sha(core) == args.core_sha256
    if args.inside:
        assert os.geteuid() == 0
        for name in ['net', 'mnt', 'user']:
            assert os.readlink('/proc/self/ns/' + name) != os.environ['THRONIUM_HOST_' + name.upper()]
        subprocess.run(['mount', '--make-rprivate', '/'], check=True)
        subprocess.run(['mount', '-t', 'tmpfs', '-o', 'mode=700', 'tmpfs', '/run'], check=True)
        assert subprocess.check_output(['stat', '-f', '-c', '%T', '/run'], text=True).strip() == 'tmpfs'
        def ip(*argv):
            return subprocess.check_output(['ip', *argv], text=True)
        ip('link', 'set', 'lo', 'up')
        ip('link', 'add', 'credentials-phy', 'type', 'dummy')
        ip('address', 'add', '198.18.0.1/24', 'dev', 'credentials-phy')
        ip('link', 'set', 'credentials-phy', 'up')
        ip('route', 'add', 'default', 'via', '198.18.0.254', 'dev', 'credentials-phy')
        ip('rule', 'add', 'priority', '18912', 'to', '203.0.113.0/24', 'table', 'main')
        baseline = {kind: json.loads(ip('-j', *argv)) for kind, argv in {
            'rules': ['rule'], 'routes': ['route', 'show', 'table', 'all']}.items()}
        result = subprocess.run([str(binary), '--ignored', '--exact',
            args.test_name, '--nocapture'],
            env={**os.environ, 'THRONIUM_TEST_CORE': str(core), 'THRONIUM_CREDENTIALS_FIXTURE': str(fixture)}, timeout=100)
        after = {'rules': json.loads(ip('-j', 'rule')), 'routes': json.loads(ip('-j', 'route', 'show', 'table', 'all'))}
        assert after == baseline
        assert not list(Path('/run/thronium-tun').glob('*.json'))
        assert not any(link['ifname'] == 'thronium-tun' for link in json.loads(ip('-j', 'link')))
        (out/'namespace.json').write_text(json.dumps({'baseline': baseline, 'after': after, 'journalEmpty': True, 'tunAbsent': True}, indent=2)+'\n')
        result.check_returncode()
        return
    out.mkdir(parents=True, exist_ok=False)
    sources = [Path(__file__).resolve(), fixture, fixture.with_name('vpn_auth_fixture.py'), fixture.with_name('vpn_otp_fixture.py')]
    before = {str(path): sha(path) for path in sources}
    for source in sources:
        shutil.copy2(source, out/source.name)
    (out/'source-before.json').write_text(json.dumps(before, indent=2)+'\n')
    host = {name: Path('/proc/net/'+name).read_bytes() for name in ['route', 'ipv6_route']}
    dns = sha('/etc/resolv.conf')
    env = {**os.environ, **{'THRONIUM_HOST_'+name.upper(): os.readlink('/proc/self/ns/'+name) for name in ['net', 'mnt', 'user']},
        'DBUS_SYSTEM_BUS_ADDRESS': 'unix:path='+str(out/'no-system'), 'DBUS_SESSION_BUS_ADDRESS': 'unix:path='+str(out/'no-session')}
    for key in ['HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'http_proxy', 'https_proxy', 'all_proxy']:
        env.pop(key, None)
    command = ['unshare', '--user', '--map-root-user', '--net', '--mount', sys.executable, str(Path(__file__).resolve()),
        '--inside', '--test-name', args.test_name, '--core', str(core), '--core-sha256', args.core_sha256, '--test-binary', str(binary), '--fixture', str(fixture), '--artifacts', str(out)]
    (out/'command.json').write_text(json.dumps(command, indent=2)+'\n')
    with (out/'run.log').open('w') as log:
        result = subprocess.run(command, env=env, stdout=log, stderr=subprocess.STDOUT, timeout=120)
    unchanged = all(Path('/proc/net/'+name).read_bytes() == content for name, content in host.items()) and sha('/etc/resolv.conf') == dns
    drift = {path: sha(path) for path, old in before.items() if sha(path) != old}
    summary = {'passed': result.returncode == 0 and unchanged and not drift, 'exitCode': result.returncode,
        'coreSha256': sha(core), 'testBinarySha256': sha(binary), 'sourceChanges': drift, 'hostRoutesAndDnsUnchanged': unchanged}
    (out/'summary.json').write_text(json.dumps(summary, indent=2)+'\n')
    print((out/'run.log').read_text())
    print(json.dumps(summary, indent=2))
    assert summary['passed']


if __name__ == '__main__':
    main()
