"""Real Qt .thrbackup scope fixtures; regenerate with the independent Qt writer."""

import copy
import hashlib
import json
import pathlib
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import qt_snapshot

DIRECTORY = pathlib.Path(__file__).with_name("fixtures") / "legacy-routing"
NAMES = ["Imported route SOCKS 🦊", "Imported route HTTP"]
SECRETS = [
    "legacy-route-fixture-password",
    "legacy-route-dns-header-secret",
    "metadata-secret-fixture",
    "CREATE TABLE",
    "SQLite format 3",
]
DNS = {
    "servers": [
        {
            "type": "udp",
            "tag": "dns-direct",
            "server": "127.0.0.1",
            "server_port": 43530,
        },
        {
            "type": "https",
            "tag": "dns-proxy",
            "server": "127.0.0.2",
            "server_port": 43531,
            "path": "/dns-query",
            "headers": {"X-Fixture-Key": ["legacy-route-dns-header-secret"]},
            "tls": {"enabled": True, "server_name": "fixture.invalid"},
        },
    ],
    "rules": [{"domain_suffix": ["fixture.invalid"], "server": "dns-proxy"}],
    "final": "dns-direct",
    "disable_cache": True,
}
RAW = {
    "rules": [
        {
            "type": "logical",
            "mode": "and",
            "rules": [
                {"network": "tcp"},
                {
                    "type": "logical",
                    "mode": "or",
                    "invert": True,
                    "rules": [{"domain": "blocked.invalid"}, {"port": 53}],
                },
            ],
            "outbound": -2,
        }
    ],
    "final": -2,
    "find_process": False,
}


def database(path, references=True, blocked=False, generated=None):
    ddl = qt_snapshot.ddl("RoutesRepo", 2)
    with sqlite3.connect(path) as db:
        for statement in ddl:
            db.execute(statement)
        db.executescript("""CREATE TABLE profiles(id INTEGER PRIMARY KEY,type TEXT NOT NULL,name TEXT,gid INTEGER NOT NULL,outbound_json TEXT NOT NULL);
CREATE TABLE groups(id INTEGER PRIMARY KEY,name TEXT NOT NULL,profiles_json TEXT,front_proxy_id INTEGER,landing_proxy_id INTEGER,url TEXT);
CREATE TABLE groups_order(group_id INTEGER PRIMARY KEY,display_order INTEGER);
CREATE TABLE settings(key TEXT PRIMARY KEY,value TEXT NOT NULL);""")
        for pid, kind, name in [(41, "socks", NAMES[0]), (42, "http", NAMES[1])]:
            config = {
                "type": kind,
                "tag": name,
                "server": "127.0.0.1",
                "server_port": 31300 + pid,
                "username": "fixture",
                "password": SECRETS[0],
            }
            if kind == "socks":
                config["version"] = "5"
            db.execute(
                "INSERT INTO profiles VALUES(?,?,?,?,?)",
                (pid, kind, name, 0, json.dumps(config, ensure_ascii=False)),
            )
        db.execute(
            "INSERT INTO groups VALUES(?,?,?,?,?,?)",
            (0, "Imported routing sources", "[42,41]", -1, -1, ""),
        )
        db.execute("INSERT INTO groups_order VALUES(?,?)", (0, 0))
        db.executemany(
            "INSERT INTO route_profiles(id,name,default_outbound_id,is_raw,raw_route,created_at,updated_at) VALUES (?,?,?,?,?,?,?)",
            [
                (1, "Imported structured routing 🇷🇺", -2, 0, "", 1, 1),
                (2, "Imported raw 日本", -2, 1, json.dumps(RAW), 1, 1),
            ],
        )
        db.executemany(
            "INSERT INTO route_rules(route_profile_id,rule_order,name,type,domain_suffix_json,outbound_id) VALUES (?,?,?,?,?,?)",
            [
                (
                    1,
                    0,
                    "Auxiliary",
                    1,
                    '["aux.fixture.invalid"]',
                    41 if references else -1,
                ),
                (1, 4, "Direct", 2, '["local.invalid"]', -2),
                (1, 8, "Reject", 3, '["blocked.invalid"]', -3),
            ],
        )
        if blocked:
            db.execute("UPDATE route_profiles SET prevent_modifications=1 WHERE id=2")
        db.executemany(
            "INSERT INTO settings VALUES(?,?)",
            [
                ("use_dns_object", "true"),
                ("dns_object", json.dumps(DNS)),
                ("current_route_id", "2"),
                ("remember_id", "41"),
                ("outbound_domain_strategy", "prefer_ipv4"),
            ],
        )
        if generated:
            values = {
                "use_dns_object": "false",
                "remote_dns": "tcp://127.0.0.1:43531",
                "direct_dns": "localhost"
                if generated == "local"
                else "127.0.0.1:43530",
                "core_box_underlying_dns": "127.0.0.1:43530",
                "dns_final_out": "direct",
                "direct_dns_disable_ipv6": "true",
                "remote_dns_disable_ipv6": "true",
                "dns_disable_cache": "true",
                "dns_predefined_rules": json.dumps(
                    [
                        "127.0.0.21 override.fixture.invalid alias.fixture.invalid",
                        "::1 v6.fixture.invalid",
                    ]
                ),
            }
            if generated == "blocked":
                values["fakedns"] = "true"
            db.executemany(
                "INSERT OR REPLACE INTO settings VALUES(?,?)", values.items()
            )


def oracle_expected(path, oracle, root, name):
    with sqlite3.connect(path) as db:
        db.row_factory = sqlite3.Row
        settings = dict(db.execute("SELECT key,value FROM settings").fetchall())
        # The function oracle accepts C++ member names; its input is not SQLite.
        members = qt_snapshot.members()
        settings = {members.get(key, key): value for key, value in settings.items()}
        cases = []
        for route in db.execute("SELECT * FROM route_profiles ORDER BY id"):
            rules = [
                {"order": row["rule_order"], "kind": row["type"], "columns": dict(row)}
                for row in db.execute(
                    "SELECT * FROM route_rules WHERE route_profile_id=? ORDER BY rule_order",
                    (route["id"],),
                )
            ]
            cases.append(
                {
                    "id": route["name"],
                    "settings": settings,
                    "rules": rules,
                    "raw": bool(route["is_raw"]),
                    "raw_route": json.loads(route["raw_route"])
                    if route["is_raw"]
                    else {},
                }
            )
    source = root / (name + "-oracle-input.json")
    source.write_text(json.dumps(cases, ensure_ascii=False))
    result = json.loads(subprocess.check_output([str(oracle), str(source)], text=True))
    assert all(not row["error"] for row in result["results"]), result
    return {
        "inputs": cases,
        "results": result["results"],
        "qtRuntime": result["qtRuntime"],
    }


def generate(writer, oracle):
    expected = {}
    DIRECTORY.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="thronium-routing-goldens-") as folder:
        root = pathlib.Path(folder)
        for name, refs, blocked, mask, generated in [
            ("mixed", True, False, 7, None),
            ("routes-only", False, False, 6, None),
            ("blocked-route", False, True, 7, None),
            ("no-settings", False, False, 3, None),
            ("no-routes", False, False, 5, None),
            ("references-no-profiles", True, False, 6, None),
            ("generated", False, False, 6, "normal"),
            ("generated-local", False, False, 6, "local"),
            ("generated-blocked", False, False, 7, "blocked"),
        ]:
            path = root / (name + ".sqlite")
            database(path, refs, blocked, generated)
            if generated and generated != "blocked":
                expected[name] = oracle_expected(path, oracle, root, name)
            output = root / name
            output.mkdir()
            qt = subprocess.check_output(
                [str(writer), str(output), str(path)], text=True
            ).strip()
            shutil.copyfile(
                output / f"parts-{mask:02}.thrbackup", DIRECTORY / (name + ".thrbackup")
            )
    manifest = {
        "qtRuntime": qt,
        "writer": "desktop/tests/thrbackup_writer.py",
        "ddl": qt_snapshot.origin("RoutesRepo"),
        "profiles": 2,
        "groups": 1,
        "routes": 2,
        "rules": 3,
        "dns": DNS,
        "raw": RAW,
        "profileNames": NAMES,
        "generatedOracle": expected,
        "dnsOracle": "desktop/engine/src/legacy_backup/routes/generated_dns/fixtures/qt-oracle-manifest.json",
        "sha256": {
            p.name: hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(DIRECTORY.glob("*.thrbackup"))
        },
    }
    (DIRECTORY / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n"
    )
    print(f"Qt{qt}: {len(manifest['sha256'])} scope fixtures")


if __name__ == "__main__":
    generate(pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2]))
