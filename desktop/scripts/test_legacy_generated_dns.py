#!/usr/bin/env python3
"""Qt-derived generated DNS packet flow through an owned core and local fixtures."""

import argparse
import hashlib
import json
import pathlib
import shutil
import subprocess
import tempfile

desktop = pathlib.Path(__file__).resolve().parents[1]
host = next(
    line[6:]
    for line in subprocess.check_output(["rustc", "-vV"], text=True).splitlines()
    if line.startswith("host: ")
)
suffix = ".exe" if "windows" in host else ""
parser = argparse.ArgumentParser()
parser.add_argument(
    "--core",
    type=pathlib.Path,
    default=desktop / "src-tauri/binaries" / f"ThroniumCore-{host}{suffix}",
)
parser.add_argument(
    "--artifacts",
    type=pathlib.Path,
    default=desktop / "test-results/legacy-generated-dns-validation",
)
parser.add_argument("--explicit-only", action="store_true")
args = parser.parse_args()
core = args.core.resolve()
if not core.is_file():
    raise SystemExit("Missing core: provide --core or build the sidecar first")
artifacts = args.artifacts.resolve()
artifacts.mkdir(parents=True, exist_ok=True)
summary = artifacts / "legacy-generated-dns-core-summary.json"
summary.unlink(missing_ok=True)
source_files = [
    "engine/src/bin/legacy-generated-dns-smoke.rs",
    "scripts/test_legacy_generated_dns.py",
    "engine/src/legacy_backup/routes/generated_dns.rs",
    "engine/src/legacy_backup/routes/generated_dns/fixtures/golden.json",
    "engine/src/routing/legacy_context.rs",
    "engine/src/routing/legacy_dns.rs",
    "engine/src/legacy_backup/routes/dns.rs",
    "engine/src/legacy_backup/routes/dns/synthetic.rs",
    "engine/src/routing.rs",
    "engine/src/lib.rs",
]
source_hashes = {
    name: hashlib.sha256((desktop / name).read_bytes()).hexdigest()
    for name in source_files
}
with (artifacts / "legacy-generated-dns-core.log").open("w") as log:

    def run(command, limit=240):
        log.write("$ " + " ".join(map(str, command)) + "\n")
        log.flush()
        try:
            result = subprocess.run(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=limit,
            )
        except subprocess.TimeoutExpired as error:
            output = error.stdout or ""
            if isinstance(output, bytes):
                output = output.decode(errors="replace")
            log.write(output + f"\nFAILED: timeout after {limit} seconds\n")
            log.flush()
            raise
        log.write(result.stdout)
        log.flush()
        print(result.stdout, end="", flush=True)
        result.check_returncode()
        return result.stdout

    run(
        [
            "cargo",
            "build",
            "--offline",
            "--locked",
            "--manifest-path",
            str(desktop / "engine/Cargo.toml"),
            "--bin",
            "legacy-generated-dns-smoke",
            "-j",
            "2",
        ]
    )
    with tempfile.TemporaryDirectory(prefix="thronium-legacy-generated-dns-") as folder:
        folder = pathlib.Path(folder)
        shutil.copy2(core, folder / ("ThroniumCore" + suffix))
        shutil.copy2(
            desktop / "engine/target/debug" / ("legacy-generated-dns-smoke" + suffix),
            folder / ("Thronium" + suffix),
        )
        hashes = {
            name: hashlib.sha256((folder / (name + suffix)).read_bytes()).hexdigest()
            for name in ["Thronium", "ThroniumCore"]
        }
        (artifacts / "legacy-generated-dns-core-binaries.json").write_text(
            json.dumps(hashes, indent=2) + "\n"
        )
        output = run([str(folder / ("Thronium" + suffix)), *(["--explicit-only"] if args.explicit_only else [])], 120)
        checks = [line[5:] for line in output.splitlines() if line.startswith("PASS ")]
        observations = [
            json.loads(line[13:])
            for line in output.splitlines()
            if line.startswith("OBSERVATIONS ")
        ]
        if len(checks) != (1 if args.explicit_only else 10) or len(observations) != 1:
            raise SystemExit("Incomplete fixture result")
        after_hashes = {
            name: hashlib.sha256((desktop / name).read_bytes()).hexdigest()
            for name in source_files
        }
        if after_hashes != source_hashes:
            raise SystemExit(
                "Tracked source drifted during compilation/execution; rerun stable sources"
            )
        summary.write_text(
            json.dumps(
                {
                    "checks": len(checks),
                    "passed": checks,
                    "observations": observations[0],
                    "binaries": hashes,
                    "sources": source_hashes,
                    "sourceDrift": [],
                    "scope": "Actual imported inline rule-set DNS A/NODATA, hosts, FakeIP and fallback to owned UDP through SOCKS5" if args.explicit_only else "Actual SOCKS5 UDP association, UDP/TCP DNS, predefined records, system hosts, FakeIP with IPv6 on/off, AAAA/NXDOMAIN guards and actual Xray VLESS A-only server resolution for UseIPv4/ForceIPv4; no TUN, OS proxy or remote traffic",
                },
                indent=2,
            )
            + "\n"
        )
print(f"Legacy routing packet-flow report: {summary}")
