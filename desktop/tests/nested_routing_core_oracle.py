#!/usr/bin/env python3
"""Run the independent nested-rule oracle against one pinned release core."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile

desktop = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser()
parser.add_argument('--core', type=Path, required=True)
parser.add_argument('--core-sha256', required=True)
parser.add_argument('--artifacts', type=Path, required=True)
args = parser.parse_args()
core, output = args.core.resolve(), args.artifacts.resolve()
sha = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
assert sha(core) == args.core_sha256, 'Pinned core SHA mismatch'
output.mkdir(parents=True, exist_ok=False)
build = ['cargo', 'test', '--offline', '--locked', '--manifest-path', str(desktop / 'engine/Cargo.toml'),
         '--test', 'nested_routing_oracle', '--no-run', '--message-format=json']
result = subprocess.run(build, capture_output=True, text=True, timeout=300)
(output / 'build.log').write_text(result.stdout + result.stderr)
result.check_returncode()
artifacts = [json.loads(line) for line in result.stdout.splitlines() if line.startswith('{')]
test = next(Path(item['executable']) for item in artifacts if item.get('reason') == 'compiler-artifact'
            and item.get('target', {}).get('name') == 'nested_routing_oracle' and item.get('executable'))
with tempfile.TemporaryDirectory(prefix='thronium-nested-routing-oracle-') as directory:
    directory = Path(directory)
    shutil.copy2(core, directory / 'ThroniumCore')
    shutil.copy2(test, directory / 'Thronium')
    binaries = {name: sha(directory / name) for name in ['Thronium', 'ThroniumCore']}
    command = [str(directory / 'Thronium'), '--exact', 'pinned_core_nested_rule_truth_table', '--ignored', '--nocapture']
    (output / 'commands.json').write_text(json.dumps(dict(build=build, run=command, binaries=binaries), indent=2) + '\n')
    result = subprocess.run(command, capture_output=True, text=True, timeout=180)
    (output / 'core.log').write_text(result.stdout + result.stderr)
    print(result.stdout, end='', flush=True)
    print(result.stderr, end='', flush=True)
    result.check_returncode()
observations = [json.loads(line[len('NESTED_ORACLE_JSON '):]) for line in result.stdout.splitlines()
                if line.startswith('NESTED_ORACLE_JSON ')]
assert len(observations) == 1 and observations[0]['httpResponses'] == 46
module = desktop / '.tools/core-overlay/sing-box@v1.11.16-0.20260909122315-b801a09c9742'
sources = [Path(__file__), desktop / 'engine/tests/nested_routing_oracle.rs',
           desktop / 'engine/tests/fixtures/nested-routing/matrix.json',
           desktop / 'engine/tests/fixtures/nested-routing/action_keys.go',
           desktop / 'engine/tests/fixtures/nested-routing/action_keys.json', desktop / 'engine/src/transport.rs',
           module / 'option/rule.go', module / 'option/rule_nested.go', module / 'option/rule_action.go',
           module / 'option/outbound.go', module / 'route/rule/rule_abstract.go', module / 'route/rule/rule_default.go']
hashes = {str(path.relative_to(desktop)): sha(path) for path in sources}
for source in sources:
    destination = output / 'sources' / source.relative_to(desktop)
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, destination)
(output / 'summary.json').write_text(json.dumps(dict(passed=True, exitCode=result.returncode,
    sourceSHA256=hashes, binaries=binaries, observation=observations[0],
    independentOf='No current/future routing UI tree model or Engine routing compiler used; handwritten raw match JSON sent directly to core RPC.'), indent=2) + '\n')
print(f'Nested routing oracle report: {output / "summary.json"}')
