"""Native chooser + scope review of real Qt backups; isolated library, loopback only."""

import contextlib
import copy
import hashlib
import json
import pathlib
import shutil
import socket
import socketserver
import tempfile
import threading
import time
import uuid
from legacy_routing_fixtures import DIRECTORY, DNS, RAW, NAMES, SECRETS
from native_dialogs import file_dialog


def run(h):
    command, click, wait_for, js, check, screenshot = (
        h[k] for k in ("command", "click", "wait_for", "js", "check", "screenshot")
    )
    request, base = h["request"], h["base"]
    initial = command("snapshot")
    geometry = request("GET", base + "/window/rect")
    connection = None
    audit = None
    manifest = json.loads((DIRECTORY / "manifest.json").read_text())
    for name, digest in manifest["sha256"].items():
        assert hashlib.sha256((DIRECTORY / name).read_bytes()).hexdigest() == digest

    class Echo(socketserver.BaseRequestHandler):
        def handle(self):
            with contextlib.suppress(OSError):
                while data := self.request.recv(65536):
                    self.request.sendall(data)

    class Server(socketserver.ThreadingTCPServer):
        allow_reuse_address = True
        daemon_threads = True

    server = Server(("127.0.0.1", 0), Echo)
    threading.Thread(target=server.serve_forever, daemon=True).start()

    def settings():
        click(".primary-nav button:nth-child(5)")
        wait_for('return !!document.querySelector("[data-settings-section=backup]")')
        click("[data-settings-section=backup]")
        wait_for('return !!document.querySelector("#backup-open")')

    def text(selector):
        return js(
            'return document.querySelector(arguments[0])?.textContent || ""', selector
        )

    def previews():
        return js("return window.__legacyRoutingAudit?.previews || []")

    def latest():
        return previews()[-1]

    def language():
        return command("snapshot")["preferences"]["language"]

    def open_file(path=None):
        count = len(previews())
        click("#backup-open")
        file_dialog(
            "Открыть резервную копию" if language() == "ru" else "Open backup",
            path,
            opening=True,
        )
        wait_for('return !document.querySelector("#backup-open").disabled')
        if path is not None:
            wait_for(
                "return window.__legacyRoutingAudit.previews.length > " + str(count)
            )
            wait_for('return !!document.querySelector("#backup-confirm")')
            return latest()

    def close():
        count = js("return window.__legacyRoutingAudit.discards")
        click(".modal-head .icon-button")
        wait_for('return !document.querySelector("dialog")')
        wait_for("return window.__legacyRoutingAudit.discards > " + str(count))

    def scope(name, enabled):
        selector = "#legacy-scope-" + name
        if (
            js("return document.querySelector(arguments[0]).checked", selector)
            != enabled
        ):
            count = len(previews())
            click(selector)
            wait_for(
                "return window.__legacyRoutingAudit.previews.length > " + str(count)
            )
            wait_for('return !document.querySelector("#backup-refresh").disabled')
        return latest()

    def refresh():
        count = len(previews())
        click("#backup-refresh")
        wait_for("return window.__legacyRoutingAudit.previews.length > " + str(count))
        wait_for(
            'return !document.querySelector("#backup-refresh").disabled && !document.querySelector("#backup-acknowledge").checked'
        )
        return latest()

    def apply():
        click("#backup-acknowledge")
        click("#backup-confirm")
        wait_for('return !document.querySelector("dialog")')
        wait_for('return !!document.querySelector("#backup-notice")')

    def parts_scopes(preview):
        return {k: preview["legacy"]["scopes"][k] for k in ("profiles", "routes")}

    def state(label):
        path = root / (label + "-" + str(time.monotonic_ns()) + ".json")
        click("#backup-save")
        file_dialog(
            "Сохранить резервную копию" if language() == "ru" else "Save backup", path
        )
        wait_for('return !document.querySelector("#backup-save").disabled')
        deadline = time.monotonic() + 5
        while not path.exists() and time.monotonic() < deadline:
            time.sleep(0.05)
        return json.loads(path.read_text())["library"], path

    def undo():
        click("#backup-undo")
        wait_for('return !!document.querySelector("#backup-confirm")')
        apply()

    def reject(name, payload, code):
        try:
            command(name, payload)
        except RuntimeError as error:
            assert code in str(error), str(error)
        else:
            raise AssertionError(f"{name} accepted forbidden action")

    def safe(preview):
        return not any(
            secret in json.dumps(preview, ensure_ascii=False)
            or secret in js("return document.body.textContent")
            for secret in SECRETS
        )

    def dns_follow(enabled):
        previous = command("settings")["dns"]
        command(
            "saveSettings",
            {
                "section": "dns",
                "previous": previous,
                "values": {**previous, "enable_dns_routing": enabled},
            },
        )

    def underlying(value):
        previous = command("settings")["core"]
        command(
            "saveSettings",
            {
                "section": "core",
                "previous": previous,
                "values": {**previous, "core_box_underlying_dns": value},
            },
        )

    def activate(profile_id):
        routing = command("routing")
        routing["active"] = profile_id
        command("saveRouting", routing)

    def routing_page():
        click(".primary-nav button:nth-child(1)")
        wait_for('return !document.querySelector("#route-profile-select")')
        click(".primary-nav button:nth-child(2)")
        wait_for('return !!document.querySelector("#route-profile-select")')

    def choose_route(profile_id):
        js(
            'const e=document.querySelector("#route-profile-select");e.value=arguments[0];e.dispatchEvent(new Event("change",{bubbles:true}));',
            profile_id,
        )

    def echo(label):
        body = ("legacy-routing-" + label).encode()
        connection.sendall(body)
        received = b""
        while len(received) < len(body):
            part = connection.recv(len(body) - len(received))
            if not part:
                break
            received += part
        return received == body

    def start_echo(profile_id, port):
        command("connect", {"id": profile_id})
        sock = socket.create_connection(("127.0.0.1", port), timeout=5)
        target = "127.0.0.1:" + str(server.server_address[1])
        sock.sendall(f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n".encode())
        headers = b""
        while b"\r\n\r\n" not in headers:
            part = sock.recv(4096)
            assert part
            headers += part
        assert b" 200 " in headers.split(b"\r\n", 1)[0]
        return sock

    with tempfile.TemporaryDirectory(prefix="thronium-routing-ui-") as directory:
        root = pathlib.Path(directory)
        copies = {}
        for name in manifest["sha256"]:
            copies[name] = root / name
            shutil.copyfile(DIRECTORY / name, copies[name])
        try:
            command("disconnect")
            command(
                "preferences",
                {**initial["preferences"], "language": "en", "theme": "dark"},
            )
            wait_for('return document.documentElement.lang==="en"')
            settings()
            js(
                """const original=window.fetch;window.__legacyRoutingAudit={original,previews:[],discards:0};window.fetch=function(input,options){let name=null;try{const body=JSON.parse(options?.body||'{}');if(String(input).includes('/app_command'))name=body.name;}catch{}const result=original.apply(this,arguments);if(['readBackup','legacyBackupScopes','refreshBackupPreview','previewPreviousBackup'].includes(name)){result.then(response=>response.clone().json()).then(value=>{const preview=value?.preview||value;if(preview?.token&&preview?.current&&preview?.incoming)window.__legacyRoutingAudit.previews.push(preview);}).catch(()=>{});}if(name==='discardBackupPreview')result.then(response=>{if(response.ok)window.__legacyRoutingAudit.discards+=1;}).catch(()=>{});return result;};"""
            )
            baseline, baseline_path = state("baseline")
            with socket.socket() as available:
                available.bind(("127.0.0.1", 0))
                port = available.getsockname()[1]
            command("connectionSettings", {"mode": "local", "port": port})
            existing = command(
                "saveProfile",
                {
                    "name": "Current route fixture",
                    "groupId": "personal",
                    "kind": "sing-box-outbound",
                    "config": {"type": "direct"},
                },
            )["id"]
            command("select", {"id": existing})
            routing = command("routing")
            current_id = routing["active"]
            routing["profiles"][0]["mode"] = "direct"
            routing["profiles"][0]["name"] = "Current routing retained"
            command("saveRouting", routing)
            dns_follow(True)
            before, _ = state("before")
            open_file()
            check(
                not js('return !!document.querySelector("dialog")')
                and state("cancel-chooser")[0] == before,
                "native chooser cancellation preserves the entire current library",
            )
            preview = open_file(copies["mixed.thrbackup"])
            check(
                parts_scopes(preview) == {"profiles": True, "routes": False}
                and preview["legacy"]["canApply"]
                and preview["incoming"]["routingProfiles"]
                == preview["current"]["routingProfiles"],
                "mixed Qt backup defaults to profiles only, leaving route scope opt-in",
            )
            old_token = preview["token"]
            preview = scope("routes", True)
            check(
                preview["legacy"]["mode"] == "add-selected"
                and preview["legacy"]["routeCount"] == 2
                and preview["incoming"]["routingProfiles"]
                == preview["current"]["routingProfiles"] + 2
                and "Import selected sections" in text("#modal-title"),
                "route checkbox updates complete additive counts and selected-sections title",
            )
            reject("restoreBackup", {"token": old_token}, "backup_preview_expired")
            check(
                preview["token"] != old_token
                and not js(
                    'return document.querySelector("#backup-acknowledge").checked'
                ),
                "scope changes invalidate the previous token and require fresh acknowledgement",
            )
            check(
                preview["legacy"]["canApply"]
                and "legacy_routing_dns_follow_conflict"
                in preview["legacy"]["requirements"]
                and "can be imported now" in text("#legacy-route-requirements"),
                "current DNS-follow conflict is explained while inactive preset import remains allowed",
            )
            check(
                safe(preview),
                "route scope preview reveals no source DNS headers, profile passwords, SQL or private metadata",
            )
            missing = scope("profiles", False)
            check(
                not missing["legacy"]["canApply"]
                and any(
                    i["code"] == "legacy_routes_require_profiles"
                    for i in missing["legacy"]["issues"]
                )
                and js('return document.querySelector("#backup-confirm").disabled'),
                "profile references require profiles from the same selected import instead of matching current names",
            )
            reject(
                "restoreBackup", {"token": missing["token"]}, "legacy_import_blocked"
            )
            restored = scope("profiles", True)
            check(
                restored["legacy"]["canApply"],
                "re-enabling the required profile scope restores a valid complete plan",
            )
            close()
            reject(
                "restoreBackup", {"token": restored["token"]}, "backup_preview_expired"
            )
            check(
                state("cancel-scope")[0] == before,
                "closing scope review discards all pending additions without changing current records",
            )

            preview = open_file(copies["routes-only.thrbackup"])
            check(
                parts_scopes(preview) == {"profiles": False, "routes": False}
                and not preview["legacy"]["canApply"]
                and js(
                    'return document.querySelector("#legacy-scope-profiles").disabled'
                ),
                "routes-only Parts hide unrelated profile rows behind a disabled profile checkbox",
            )
            preview = scope("routes", True)
            check(
                preview["legacy"]["canApply"]
                and preview["incoming"]["profiles"] == preview["current"]["profiles"]
                and preview["incoming"]["groups"] == preview["current"]["groups"],
                "routes-only scope adds two presets without importing unselected profile/group rows",
            )
            request("POST", base + "/window/rect", {"width": 390, "height": 844})
            check(
                js(
                    'return document.querySelector("dialog").scrollWidth<=document.querySelector("dialog").clientWidth+1 && document.querySelector(".modal-footer").getBoundingClientRect().bottom<=innerHeight+1'
                ),
                "English route scopes, conflicts and footer fit the 390-pixel native window",
            )
            screenshot("legacy-routing-scopes-en-390")
            command(
                "preferences",
                {
                    **command("snapshot")["preferences"],
                    "language": "ru",
                    "theme": "light",
                },
            )
            wait_for('return document.documentElement.lang==="ru"')
            refresh()
            check(
                "Импорт разделов из Throne" in text("#modal-title")
                and "Пресеты маршрутизации" in text("#legacy-import-review")
                and js(
                    'return document.querySelector("dialog").scrollWidth<=document.querySelector("dialog").clientWidth+1'
                ),
                "Russian scope review stays localized and usable at 390 pixels",
            )
            screenshot("legacy-routing-scopes-ru-390")
            command(
                "preferences",
                {
                    **command("snapshot")["preferences"],
                    "language": "en",
                    "theme": "dark",
                },
            )
            wait_for('return document.documentElement.lang==="en"')
            refresh()
            request("POST", base + "/window/rect", {"width": 1280, "height": 860})
            close()
            before_routes, _ = state("before-routes")
            open_file(copies["routes-only.thrbackup"])
            scope("routes", True)
            apply()
            after_routes, _ = state("after-routes")
            check(
                after_routes["profiles"] == before_routes["profiles"]
                and after_routes["groups"] == before_routes["groups"]
                and after_routes["settings"] == before_routes["settings"]
                and after_routes["preferences"] == before_routes["preferences"]
                and after_routes["routing"]["active"]
                == before_routes["routing"]["active"],
                "inactive route-only import keeps current selection, profile records, preferences and global settings exactly",
            )
            added_routes = after_routes["routing"]["profiles"][
                len(before_routes["routing"]["profiles"]) :
            ]
            check(
                len(added_routes) == 2
                and all(
                    p["dns"] == DNS
                    and p["legacyConstraints"]
                    == {"version": 2, "xrayDnsStrategy": "UseIPv4v6"}
                    for p in added_routes
                ),
                "native saved backup contains exact imported DNS JSON and runtime constraints for both presets",
            )
            undo()
            check(
                state("undo-routes")[0] == before_routes,
                "Previous library undoes a route-only import exactly, including routing revision and settings",
            )

            preview = open_file(copies["mixed.thrbackup"])
            scope("routes", True)
            new_current = command(
                "saveProfile",
                {
                    "name": "Concurrent local record",
                    "groupId": "personal",
                    "kind": "sing-box-outbound",
                    "config": {"type": "direct"},
                },
            )["id"]
            click("#backup-acknowledge")
            click("#backup-confirm")
            wait_for(
                'return document.querySelector("dialog .desktop-inline-error")?.textContent.includes("changed")'
            )
            fresh = refresh()
            check(
                fresh["token"] != preview["token"]
                and fresh["current"]["profiles"] == preview["current"]["profiles"] + 1
                and parts_scopes(fresh) == {"profiles": True, "routes": True}
                and not js(
                    'return document.querySelector("#backup-acknowledge").checked'
                ),
                "stale review rejects application and refresh retains scopes while incorporating concurrent records",
            )
            close()
            before_mixed, _ = state("before-mixed")
            open_file(copies["mixed.thrbackup"])
            scope("routes", True)
            apply()
            mixed, _ = state("mixed")
            added = mixed["profiles"][len(before_mixed["profiles"]) :]
            groups = mixed["groups"][len(before_mixed["groups"]) :]
            presets = mixed["routing"]["profiles"][
                len(before_mixed["routing"]["profiles"]) :
            ]
            check(
                len(added) == 2
                and len(groups) == 1
                and len(presets) == 2
                and mixed["profiles"][: len(before_mixed["profiles"])]
                == before_mixed["profiles"]
                and mixed["routing"]["active"] == current_id
                and mixed["settings"] == before_mixed["settings"],
                "combined import adds the entire profiles/groups/routes plan and keeps concurrent/current records and active policy",
            )
            ids = [item["id"] for item in added + groups + presets]
            check(
                len(set(ids)) == 5 and all(str(uuid.UUID(i)) == i for i in ids),
                "all imported profile, group and route identities are fresh UUIDs",
            )
            by_name = {p["name"]: p for p in added}
            structured = next(
                p for p in presets if p["name"].startswith("Imported structured")
            )
            raw_preset = next(
                p for p in presets if p["name"].startswith("Imported raw")
            )
            check(
                structured["rules"][2]["config"]["outbound"]
                == "profile:" + by_name[NAMES[0]]["id"]
                and all(p["dns"] == DNS for p in presets),
                "saved route references point to the simultaneously imported UUID and preserve the complete DNS policy",
            )
            expected = copy.deepcopy(RAW["rules"][0])
            expected["outbound"] = "direct"
            check(
                raw_preset["rules"][0]["config"] == expected
                and len(raw_preset["rules"]) == 1,
                "saved raw nested AND/OR/invert tree stays exact without extra generated rules",
            )

            connection = start_echo(existing, port)
            settings()
            preview = open_file(copies["routes-only.thrbackup"])
            scope("routes", True)
            click("#backup-acknowledge")
            check(
                js('return document.querySelector("#backup-confirm").disabled')
                and echo("scope-review"),
                "route scope review during a live connection keeps the same CONNECT stream usable and disables import",
            )
            reject(
                "restoreBackup", {"token": latest()["token"]}, "backup_disconnect_first"
            )
            check(
                echo("scope-backend"),
                "backend rejects active route import independently without interrupting the held stream",
            )
            close()
            routing_page()
            choose_route(raw_preset["id"])
            wait_for(
                'return document.querySelector(".desktop-inline-error")?.textContent.includes("Follow domain") && !document.querySelector("#route-profile-select").disabled'
            )
            check(
                command("routing")["active"] == current_id and echo("ui-guard"),
                "routing UI checks an imported preset before selection and preserves active policy and traffic on a setting conflict",
            )
            activate(raw_preset["id"])
            reject("checkRouting", raw_preset, "legacy_routing_dns_follow_conflict")
            reject("applyRouting", {}, "legacy_routing_dns_follow_conflict")
            check(
                echo("backend-apply-guard"),
                "direct backend Check and Apply also refuse incompatible imported policy before stopping the active connection",
            )
            activate(current_id)
            connection.close()
            connection = None
            command("disconnect")
            dns_follow(False)
            routing_page()
            choose_route(raw_preset["id"])
            wait_for(
                'return document.querySelector("#route-profile-select").value === '
                + json.dumps(raw_preset["id"])
                + ' && !document.querySelector("#route-profile-select").disabled'
            )
            check(
                command("routing")["active"] == raw_preset["id"],
                "resolving the setting conflict lets actual routing UI run core validation and select the imported preset",
            )
            connection = start_echo(existing, port)
            check(
                echo("imported-preset"),
                "the selected imported raw preset carries a real local CONNECT after explicit connection",
            )
            connection.close()
            connection = None
            command("disconnect")
            activate(current_id)
            dns_follow(True)
            settings()
            undo()
            check(
                state("undo-mixed")[0] == before_mixed,
                "Previous library reverses the whole mixed import and preserves the concurrent record",
            )

            stable, _ = state("before-blockers")
            preview = open_file(copies["blocked-route.thrbackup"])
            check(
                preview["legacy"]["canApply"],
                "an unsupported route does not block the default profiles-only scope",
            )
            # A protected raw route is imported verbatim (835c997e); the review
            # names it instead of refusing the whole selected addition.
            protected = scope("routes", True)
            check(
                protected["legacy"]["canApply"]
                and any(
                    i["code"] == "legacy_route_raw_verbatim"
                    for i in protected["legacy"]["issues"]
                )
                and any(
                    i["code"] == "legacy_backup_unknown_files_deferred"
                    for i in protected["legacy"]["issues"]
                ),
                "a protected raw route is reviewed as verbatim and extra container files are named",
            )
            close()
            for filename, route_checkbox, code in [
                ("no-settings.thrbackup", True, "legacy_route_parts_required"),
                (
                    "references-no-profiles.thrbackup",
                    True,
                    "legacy_route_reference_missing",
                ),
            ]:
                open_file(copies[filename])
                blocked = scope("routes", True)
                check(
                    not blocked["legacy"]["canApply"]
                    and any(i["code"] == code for i in blocked["legacy"]["issues"]),
                    filename
                    + " enforces authoritative Parts and reference dependencies",
                )
                close()
            preview = open_file(copies["no-routes.thrbackup"])
            check(
                js('return document.querySelector("#legacy-scope-routes").disabled')
                and preview["legacy"]["canApply"],
                "unselected Routes cannot be enabled from stale rows while selected profiles remain importable",
            )
            forged = command(
                "legacyBackupScopes",
                {
                    "token": preview["token"],
                    "scopes": {"profiles": True, "routes": True},
                },
            )
            check(
                not forged["legacy"]["canApply"]
                and any(
                    i["code"] == "legacy_route_parts_required"
                    for i in forged["legacy"]["issues"]
                ),
                "backend independently blocks a forged route scope whose source Parts excluded Routes",
            )
            command("discardBackupPreview", {"token": forged["token"]})
            close()
            check(
                state("after-blockers")[0] == stable,
                "all unsupported selected scopes leave the complete current library unchanged",
            )
            for fixture in ["generated", "generated-local"]:
                dns_follow(False)
                underlying("127.0.0.1:43532" if fixture == "generated-local" else "")
                before_generated, _ = state("before-" + fixture)
                open_file(copies[fixture + ".thrbackup"])
                preview = scope("routes", True)
                check(
                    preview["legacy"]["canApply"] and safe(preview),
                    fixture
                    + " Qt archive offers an additive route scope without exposing source DNS content",
                )
                if fixture == "generated-local":
                    check(
                        "legacy_routing_local_dns_conflict"
                        in preview["legacy"]["requirements"],
                        "generated local DNS review reports current underlying resolver conflict while allowing inactive import",
                    )
                apply()
                saved, _ = state("after-" + fixture)
                added = saved["routing"]["profiles"][
                    len(before_generated["routing"]["profiles"]) :
                ]
                expected = {
                    r["id"]: r for r in manifest["generatedOracle"][fixture]["results"]
                }
                check(
                    len(added) == 2
                    and all(p["dns"] == expected[p["name"]]["dns"] for p in added),
                    fixture
                    + " imports exact independently executed Qt DNS JSON, including predefined records, ordered selectors and final AAAA guards",
                )
                check(
                    all(
                        p["legacyConstraints"]
                        == {
                            "version": 2,
                            "xrayDnsStrategy": expected[p["name"]]["xrayStrategy"],
                        }
                        for p in added
                    ),
                    fixture
                    + " stores version 2 and source-derived Xray UseIPv4 instead of the uncapped source preference",
                )
                check(
                    all(
                        saved[key] == before_generated[key]
                        for key in ["profiles", "groups", "preferences", "settings"]
                    )
                    and saved["routing"]["active"]
                    == before_generated["routing"]["active"],
                    fixture
                    + " leaves current profiles, settings, preferences and selected routing unchanged",
                )
                raw_generated = next(
                    p for p in added if p["name"].startswith("Imported raw")
                )
                if fixture == "generated-local":
                    connection = start_echo(existing, port)
                    routing_page()
                    choose_route(raw_generated["id"])
                    wait_for(
                        'return document.querySelector(".desktop-inline-error")?.textContent.includes("local DNS override") && !document.querySelector("#route-profile-select").disabled'
                    )
                    check(
                        command("routing")["active"] == current_id
                        and echo("generated-local-ui-guard"),
                        "generated local resolver guard rejects actual UI selection before changing the held CONNECT stream",
                    )
                    activate(raw_generated["id"])
                    reject(
                        "checkRouting",
                        raw_generated,
                        "legacy_routing_local_dns_conflict",
                    )
                    reject("applyRouting", {}, "legacy_routing_local_dns_conflict")
                    check(
                        echo("generated-local-backend-guard"),
                        "version 2 backend Check and Apply preserve live traffic when current underlying DNS would alter imported local semantics",
                    )
                    activate(current_id)
                    connection.close()
                    connection = None
                    command("disconnect")
                    underlying("")
                for preset in added:
                    command("checkRouting", preset)
                check(
                    True,
                    fixture
                    + " both generated presets pass the pinned core Check after current context conflicts are removed",
                )
                routing_page()
                choose_route(raw_generated["id"])
                wait_for(
                    'return document.querySelector("#route-profile-select").value === '
                    + json.dumps(raw_generated["id"])
                    + ' && !document.querySelector("#route-profile-select").disabled'
                )
                check(
                    command("routing")["active"] == raw_generated["id"],
                    fixture
                    + " actual routing UI validates and selects generated DNS only after explicit user choice",
                )
                activate(current_id)
                settings()
                undo()
                check(
                    state("undo-" + fixture)[0] == before_generated,
                    fixture
                    + " Previous library restores the exact prior state, including constraints and global resolver setting",
                )
            underlying("")
            dns_follow(True)
            before_generated_blocked, _ = state("before-generated-blocked")
            preview = open_file(copies["generated-blocked.thrbackup"])
            check(
                preview["legacy"]["canApply"],
                "unsupported generated fake DNS dependency remains outside default profiles-only import",
            )
            # FakeDNS in generated DNS is preserved as a FakeIP policy (7e83b3e9);
            # the routes scope is now importable, only reviewed, never applied here.
            selected = scope("routes", True)
            check(
                selected["legacy"]["canApply"]
                and not any(
                    i["code"] == "legacy_dns_generated_dependency_unsupported"
                    for i in selected["legacy"]["issues"]
                ),
                "generated FakeDNS routes are reviewed as importable",
            )
            close()
            check(
                state("after-generated-blocked")[0] == before_generated_blocked,
                "a closed review adds neither profiles nor routing presets",
            )
            open_file(baseline_path)
            apply()
            check(
                state("baseline-restored")[0] == baseline
                and all(
                    hashlib.sha256(path.read_bytes()).hexdigest()
                    == manifest["sha256"][name]
                    for name, path in copies.items()
                ),
                "native baseline restore removes all fixtures and every source Qt archive remains byte-for-byte unchanged",
            )
            audit = {
                "previews": previews(),
                "sourceHashes": manifest["sha256"],
                "exactDns": True,
                "mappedUuidReferences": True,
                "sourceUnchanged": True,
                "loopbackOnly": True,
                "generatedDnsMatchesIndependentQt": True,
                "generatedXrayStrategy": "UseIPv4",
            }
        finally:
            with contextlib.suppress(Exception):
                if audit is None:
                    audit = {"previews": previews(), "failed": True}
                (
                    pathlib.Path(h["args"].artifacts) / "legacy-routing-review.json"
                ).write_text(json.dumps(audit, ensure_ascii=False, indent=2) + "\n")
            if connection:
                connection.close()
            with contextlib.suppress(Exception):
                if js('return !!document.querySelector("dialog")'):
                    close()
                command("disconnect")
                command("preferences", initial["preferences"])
                js(
                    "if(window.__legacyRoutingAudit){window.fetch=window.__legacyRoutingAudit.original;delete window.__legacyRoutingAudit;}"
                )
                click(".primary-nav button:nth-child(1)")
                request("POST", base + "/window/rect", geometry)
            server.shutdown()
            server.server_close()
