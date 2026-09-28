"""Native OTP manager, synthetic RFC keys, real clipboard/QR/files and loopback."""

import base64
import contextlib
import copy
import hashlib
import hmac
import json
import os
import pathlib
import socket
import socketserver
import subprocess
import tempfile
import threading
import time
from native_dialogs import file_dialog

KEY = base64.b32encode(b"12345678901234567890").decode().rstrip("=")
LARGE = "9007199254740993"
MAXIMUM = "9223372036854775807"


def run(h):
    command, click, fill, select, wait_for, js, check, screenshot = (
        h[k]
        for k in (
            "command",
            "click",
            "fill",
            "select",
            "wait_for",
            "js",
            "check",
            "screenshot",
        )
    )
    initial = command("snapshot")
    geometry = h["request"]("GET", h["base"] + "/window/rect")
    original_clipboard = None
    original_image = None
    try:
        original_clipboard = command("readClipboard")
    except RuntimeError:
        import gi

        gi.require_version("Gtk", "3.0")
        from gi.repository import Gtk, Gdk

        original_image = Gtk.Clipboard.get(Gdk.SELECTION_CLIPBOARD).wait_for_image()
    connection = None
    audit = {}

    class Echo(socketserver.BaseRequestHandler):
        def handle(self):
            with contextlib.suppress(OSError):
                while data := self.request.recv(8192):
                    self.request.sendall(data)

    class Server(socketserver.ThreadingTCPServer):
        allow_reuse_address = True
        daemon_threads = True

    server = Server(("127.0.0.1", 0), Echo)
    threading.Thread(target=server.serve_forever, daemon=True).start()

    def settings(section="otp"):
        click(".primary-nav button:nth-child(5)")
        wait_for(
            'return !!document.querySelector("[data-settings-section=' + section + ']")'
        )
        click("[data-settings-section=" + section + "]")
        wait_for(
            'return !!document.querySelector("'
            + ("#otp-manager" if section == "otp" else "#backup-save")
            + '")'
        )

    def list_rows():
        return command("otpList")

    def entry(id):
        return command("otpGet", {"id": id})

    def refresh():
        click("#otp-refresh")
        wait_for('return !document.querySelector("#otp-refresh").disabled')

    def row(id, selector=""):
        return "[data-otp-id=" + json.dumps(id) + "] " + selector

    def text(selector):
        return js(
            'return document.querySelector(arguments[0])?.textContent || ""', selector
        )

    def edit(id):
        click(row(id, "[data-otp-edit]"))
        wait_for('return !!document.querySelector("#otp-editor")')

    def close():
        click("dialog > .modal-head > .icon-button")
        wait_for('return !document.querySelector("dialog")')

    def privacy(value):
        return (
            KEY not in json.dumps(value)
            and "otpauth://" not in json.dumps(value)
            and '"secret"' not in json.dumps(value)
        )

    def reject(name, payload, code):
        try:
            command(name, payload)
        except RuntimeError as e:
            assert code in str(e) and KEY not in str(e), str(e)
        else:
            raise AssertionError(name + " accepted invalid OTP data")

    def import_text(value):
        click("#otp-import")
        fill("#otp-import-text", value)
        click("#otp-import-confirm")
        wait_for('return !document.querySelector("dialog")')

    def populate(value):
        for key in ["name", "issuer", "secret", "digits"]:
            fill("#otp-" + key, str(value[key]))
        select("#otp-type", value["type"])
        select("#otp-algorithm", value["algorithm"])
        fill(
            "#otp-" + ("counter" if value["type"] == "hotp" else "period"),
            str(value["counter"] if value["type"] == "hotp" else value["period"]),
        )

    def save_editor():
        click("#otp-save")
        wait_for('return !document.querySelector("#otp-editor")')

    def expected_code(value, now):
        key = base64.b32decode(value["secret"] + "=" * ((-len(value["secret"])) % 8))
        count = (
            int(value["counter"])
            if value["type"] == "hotp"
            else int(now) // value["period"]
        )
        mac = hmac.new(
            key, count.to_bytes(8, "big"), getattr(hashlib, value["algorithm"].lower())
        ).digest()
        offset = mac[-1] & 15
        number = int.from_bytes(mac[offset : offset + 4], "big") & 0x7FFFFFFF
        return str(number % (10 ** value["digits"])).zfill(value["digits"])

    def count_calls():
        return js(
            'return window.__otpAudit.calls.filter(v=>v.name==="otpCodes").length'
        )

    def install_audit():
        js(
            """const original=window.fetch;window.__otpAudit={original,calls:[],safe:[]};window.fetch=function(input,options){let name=null;try{if(String(input).includes('/app_command'))name=JSON.parse(options?.body||'{}').name}catch{}if(name)window.__otpAudit.calls.push({name,time:Date.now()});const result=original.apply(this,arguments);if(['otpList','otpSave','snapshot','readBackup','refreshBackupPreview'].includes(name))result.then(r=>r.clone().json()).then(v=>window.__otpAudit.safe.push({name,value:v})).catch(()=>{});return result;};"""
        )

    def saved_state(label):
        settings("backup")
        path = root / (label + "-" + str(time.monotonic_ns()) + ".json")
        click("#backup-save")
        file_dialog("Save backup", path)
        wait_for('return !document.querySelector("#backup-save").disabled')
        deadline = time.monotonic() + 5
        while not path.exists() and time.monotonic() < deadline:
            time.sleep(0.05)
        return json.loads(path.read_text())["library"], path

    def open_backup(path):
        click("#backup-open")
        file_dialog("Open backup", path, opening=True)
        wait_for('return !!document.querySelector("#backup-confirm")')

    def apply_backup():
        click("#backup-acknowledge")
        click("#backup-confirm")
        wait_for('return !document.querySelector("dialog")')

    def echo(label):
        value = ("OTP-loopback-" + label).encode()
        connection.sendall(value)
        output = b""
        while len(output) < len(value):
            part = connection.recv(len(value) - len(output))
            if not part:
                break
            output += part
        return output == value

    def start_echo(id, port):
        command("connect", {"id": id})
        sock = socket.create_connection(("127.0.0.1", port), timeout=5)
        target = "127.0.0.1:" + str(server.server_address[1])
        sock.sendall(f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n".encode())
        headers = b""
        while b"\r\n\r\n" not in headers:
            headers += sock.recv(4096)
        assert b" 200 " in headers.split(b"\r\n", 1)[0]
        return sock

    def upload(selector, path):
        element = h["element"](selector)
        h["request"](
            "POST",
            h["base"] + "/element/" + element + "/value",
            {"text": str(path), "value": list(str(path))},
        )

    with tempfile.TemporaryDirectory(prefix="thronium-otp-ui-") as directory:
        root = pathlib.Path(directory)
        try:
            command("disconnect")
            command(
                "preferences",
                {**initial["preferences"], "language": "en", "theme": "dark"},
            )
            wait_for('return document.documentElement.lang==="en"')
            baseline, baseline_path = saved_state("baseline")
            settings()
            install_audit()
            check(
                list_rows() == [] and "No entries yet" in text("#otp-empty"),
                "OTP panel starts empty in the isolated real application",
            )
            click("#otp-add")
            populate(
                {
                    "name": "Cancelled",
                    "issuer": "Fixture",
                    "secret": KEY,
                    "algorithm": "SHA1",
                    "type": "hotp",
                    "digits": 6,
                    "period": 30,
                    "counter": "0",
                }
            )
            close()
            check(
                list_rows() == [],
                "closing a new OTP editor discards its secret and creates no saved entry",
            )
            hotp = {
                "name": "Counter 🦊",
                "issuer": "Thronium fixture",
                "secret": KEY,
                "algorithm": "SHA1",
                "type": "hotp",
                "digits": 10,
                "period": 30,
                "counter": LARGE,
            }
            click("#otp-add")
            populate(hotp)
            check(
                js(
                    'return document.querySelector("#otp-secret").type==="password" && document.querySelector("#otp-counter").value===arguments[0]',
                    LARGE,
                ),
                "editor masks the secret and retains a counter above JavaScript safe integer range as text",
            )
            save_editor()
            a = list_rows()[0]["id"]
            check(
                {k: v for k, v in entry(a).items() if k not in ("id", "revision")}
                == hotp,
                "native Save retains the complete HOTP record and exact large counter",
            )
            check(
                privacy(list_rows())
                and privacy(command("snapshot"))
                and KEY not in js("return document.body.textContent"),
                "general snapshot and OTP metadata/list do not expose secrets, otpauth URIs or secret fields",
            )
            wait_for(
                'return /^\\d{10}$/.test(document.querySelector(arguments[0])?.textContent||"")'.replace(
                    "arguments[0]", json.dumps(row(a, "[data-otp-code]"))
                )
            )
            before = entry(a)
            for _ in range(2):
                click(row(a, "[data-otp-copy]"))
                wait_for(
                    'return document.querySelector("#otp-notice")?.textContent.includes("copied")'
                )
            check(
                command("readClipboard") == expected_code(hotp, 0)
                and entry(a) == before,
                "actual clipboard receives the fresh RFC-derived HOTP code and repeated Copy never advances its counter or revision",
            )
            edit(a)
            fill("#otp-name", "My unsaved edit")
            external = {**hotp, "name": "Concurrent saved edit"}
            changed = command(
                "otpSave", {"id": a, "revision": before["revision"], "value": external}
            )
            click("#otp-save")
            wait_for(
                'return document.querySelector("#otp-editor [role=alert]")?.textContent.includes("changed")'
            )
            check(
                js(
                    'return document.querySelector("#otp-name").value==="My unsaved edit"'
                )
                and entry(a)["name"] == external["name"],
                "stale editor save preserves both the concurrent record and unsaved user input with an explicit conflict",
            )
            close()
            refresh()
            edit(a)
            fill("#otp-counter", MAXIMUM)
            save_editor()
            hotp = {**external, "counter": MAXIMUM}
            check(
                entry(a)["counter"] == MAXIMUM,
                "editing supports i64MAX counter without rounding or scientific notation",
            )
            edit(a)
            time.sleep(1.3)
            after_open = count_calls()
            time.sleep(1.3)
            check(
                count_calls() == after_open,
                "periodic OTP code requests pause while a secret editor is open",
            )
            close()
            totp = {
                "name": "Timer 日本",
                "issuer": "Clock fixture",
                "secret": KEY,
                "algorithm": "SHA256",
                "type": "totp",
                "digits": 8,
                "period": 2,
                "counter": "0",
            }
            import_text(json.dumps({"version": 1, "otp": [totp]}))
            b = list_rows()[-1]["id"]
            wait_for(
                "return /^\\d{8}$/.test(document.querySelector("
                + json.dumps(row(b, "[data-otp-code]"))
                + ')?.textContent||"")'
            )
            first = text(row(b, "[data-otp-code]"))
            start = time.time()
            wait_for(
                "return document.querySelector("
                + json.dumps(row(b, "[data-otp-code]"))
                + ").textContent !== "
                + json.dumps(first),
                5,
            )
            now = time.time()
            current = text(row(b, "[data-otp-code]"))
            check(
                current
                in {expected_code(totp, t) for t in range(int(start) - 1, int(now) + 2)}
                and text(row(b, "[data-otp-remaining]")).strip() in {"1 s", "2 s"},
                "visible TOTP code and countdown update across a real clock boundary with independently calculated HMAC",
            )
            click(row(b, "[data-otp-up]"))
            wait_for(
                'return document.querySelector("[data-otp-id]").dataset.otpId==='
                + json.dumps(b)
            )
            check(
                [r["id"] for r in list_rows()] == [b, a],
                "actual reorder controls persist the chosen OTP order",
            )
            stale = [b, a]
            c = command("otpSave", {"value": {**totp, "name": "Concurrent order row"}})[
                "id"
            ]
            reject("otpReorder", {"previous": stale, "ids": [a, b]}, "otp_changed")
            reject(
                "otpRemove", {"id": a, "revision": before["revision"]}, "otp_changed"
            )
            check(
                [r["id"] for r in list_rows()] == [b, a, c],
                "stale reorder and delete are rejected without dropping a concurrent entry",
            )
            refresh()
            fill("#otp-search", "日本")
            check(
                js('return document.querySelectorAll("[data-otp-id]").length===1')
                and js('return document.querySelector("[data-otp-id]").dataset.otpId')
                == b,
                "OTP search filters visible entries without altering stored order",
            )
            fill("#otp-search", "")
            invalid = json.dumps(
                {
                    "version": 1,
                    "otp": [
                        {**totp, "name": "Must not be added"},
                        {
                            **totp,
                            "algorithm": "MD5",
                            "secret": "PRIVATE-INVALID-SOURCE-FIXTURE",
                        },
                    ],
                }
            )
            unchanged = list_rows()
            click("#otp-import")
            fill("#otp-import-text", invalid)
            click("#otp-import-confirm")
            wait_for('return !!document.querySelector("dialog [role=alert]")')
            check(
                list_rows() == unchanged
                and "PRIVATE-INVALID-SOURCE-FIXTURE" not in text("dialog [role=alert]"),
                "a mixed valid/invalid OTP batch fails atomically with a safe error and no partial additions",
            )
            close()
            reject("otpCodes", {"ids": [a, a]}, "otp_invalid_entry")
            check(
                list_rows() == unchanged,
                "duplicate code requests are refused without any counter or metadata mutation",
            )
            click(row(c, "[data-otp-delete]"))
            close()
            check(
                any(r["id"] == c for r in list_rows()),
                "cancelling Delete keeps the OTP record",
            )
            click(row(c, "[data-otp-delete]"))
            click("#otp-delete-confirm")
            wait_for('return !document.querySelector("dialog")')
            check(
                not any(r["id"] == c for r in list_rows()),
                "confirmed deletion removes only the selected revision",
            )

            # Explicit secret-bearing exports and native private files.
            click(row(a, "[data-otp-export]"))
            wait_for('return !!document.querySelector("#otp-export-text")')
            uri = js('return document.querySelector("#otp-export-text").value')
            check(
                "counter=" + MAXIMUM in uri and KEY in uri,
                "explicit OTP export retains the secret and exact i64MAX counter",
            )
            click("#otp-export-copy")
            wait_for(
                'return document.querySelector("dialog [role=status]")?.textContent.includes("copied")'
            )
            check(
                command("readClipboard") == uri,
                "Copy export writes the complete otpauth link to the native clipboard",
            )
            click("#otp-show-qr")
            wait_for('return !!document.querySelector("#otp-qr-image")')
            qr = js('return document.querySelector("#otp-qr-image").src').split(",", 1)[
                1
            ]
            check(
                command("decodeQrImage", {"data": qr}) == [uri],
                "actual generated OTP QR image decodes to the exact native link",
            )
            click(".otp-qr .otp-toolbar button:first-child")
            wait_for('return !document.querySelector("#otp-show-qr").disabled')
            check(
                command("readQrClipboard") == [uri],
                "native image clipboard preserves the complete OTP QR payload",
            )
            qr_path = root / "otp.png"
            click(".otp-qr .otp-toolbar button:last-child")
            file_dialog("Save QR code", qr_path)
            wait_for('return !document.querySelector("#otp-show-qr").disabled')
            check(
                qr_path.stat().st_mode & 0o777 == 0o600
                and command(
                    "decodeQrImage",
                    {"data": base64.b64encode(qr_path.read_bytes()).decode()},
                )
                == [uri],
                "native saved OTP PNG is private and decodes exactly",
            )
            link_path = root / "otp.txt"
            click("#otp-export-file")
            file_dialog("Save export", link_path)
            wait_for('return !document.querySelector("#otp-export-file").disabled')
            check(
                link_path.read_text() == uri
                and link_path.stat().st_mode & 0o777 == 0o600,
                "native otpauth text export preserves exact content with private permissions",
            )
            click("#otp-export-file")
            file_dialog("Save export")
            wait_for('return !document.querySelector("#otp-export-file").disabled')
            check(
                link_path.read_text() == uri,
                "cancelling a subsequent export preserves the existing file",
            )
            close()
            click("#otp-import")
            upload("#otp-import-file", qr_path)
            wait_for(
                'return document.querySelector("#otp-import-text").value.startsWith("otpauth://")'
            )
            check(
                js('return document.querySelector("#otp-import-text").value') == uri,
                "real QR image file input decodes through the native importer into exact editable OTP text",
            )
            click("#otp-import-confirm")
            wait_for('return !document.querySelector("dialog")')
            copy_id = list_rows()[-1]["id"]
            check(
                copy_id != a
                and {
                    k: v
                    for k, v in entry(copy_id).items()
                    if k not in ("id", "revision")
                }
                == hotp,
                "QR import creates a new identity while preserving every HOTP parameter",
            )
            click("#otp-export-all")
            wait_for('return !!document.querySelector("#otp-export-text")')
            export_json = js('return document.querySelector("#otp-export-text").value')
            json_path = root / "otp.json"
            click("#otp-export-file")
            file_dialog("Save export", json_path)
            wait_for('return !document.querySelector("#otp-export-file").disabled')
            check(
                json.loads(json_path.read_text()) == json.loads(export_json)
                and all(
                    isinstance(v["counter"], str)
                    for v in json.loads(export_json)["otp"]
                ),
                "JSON export preserves all entries and decimal-string counters for JavaScript-safe interchange",
            )
            close()
            click("#otp-import")
            upload("#otp-import-file", json_path)
            wait_for(
                'return document.querySelector("#otp-import-text").value.startsWith("{")'
            )
            count = len(list_rows())
            click("#otp-import-confirm")
            wait_for('return !document.querySelector("dialog")')
            check(
                len(list_rows()) == count + len(json.loads(export_json)["otp"]),
                "actual JSON file input adds the entire collection atomically",
            )

            # Poll only while rendered/visible, including actual window minimize.
            time.sleep(0.25)
            click(".primary-nav button:nth-child(1)")
            time.sleep(1.3)
            unmounted = count_calls()
            time.sleep(1.3)
            check(
                count_calls() == unmounted,
                "navigating away unmounts OTP and stops periodic code RPCs",
            )
            settings()
            wait_for(
                'return document.querySelector("[data-otp-code]").textContent!=="—"'
            )
            click('[data-window-action="minimize"]')
            time.sleep(1.4)
            hidden_calls = count_calls()
            time.sleep(1.3)
            hidden = js("return document.hidden")
            after_hidden = count_calls()
            subprocess.run(
                [h["args"].application],
                env=os.environ.copy(),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=True,
                timeout=12,
            )
            wait_for("return !document.hidden")
            check(
                hidden and after_hidden == hidden_calls,
                "minimizing the actual native window pauses code polling until the window becomes visible again",
            )

            for language, theme in [("en", "dark"), ("ru", "light")]:
                command(
                    "preferences",
                    {
                        **command("snapshot")["preferences"],
                        "language": language,
                        "theme": theme,
                    },
                )
                wait_for(
                    "return document.documentElement.lang===" + json.dumps(language)
                )
                h["request"](
                    "POST", h["base"] + "/window/rect", {"width": 390, "height": 844}
                )
                edit(a)
                check(
                    js(
                        'return document.querySelector("dialog").scrollWidth<=document.querySelector("dialog").clientWidth+1 && document.querySelector(".modal-footer").getBoundingClientRect().bottom<=innerHeight'
                    )
                    and ("Изменить" if language == "ru" else "Edit")
                    in text("#modal-title"),
                    language
                    + " OTP secret editor and exact large counter remain localized and usable at390 pixels",
                )
                screenshot("otp-editor-" + language + "-390")
                close()
            command(
                "preferences",
                {
                    **command("snapshot")["preferences"],
                    "language": "en",
                    "theme": "dark",
                },
            )
            wait_for('return document.documentElement.lang==="en"')
            h["request"](
                "POST", h["base"] + "/window/rect", {"width": 1280, "height": 860}
            )

            # OTP mutations during an owned live CONNECT must not restart core.
            with socket.socket() as available:
                available.bind(("127.0.0.1", 0))
                port = available.getsockname()[1]
            command("connectionSettings", {"mode": "local", "port": port})
            profile = command(
                "saveProfile",
                {
                    "name": "OTP local traffic fixture",
                    "groupId": "personal",
                    "kind": "sing-box-outbound",
                    "config": {"type": "direct"},
                },
            )["id"]
            connection = start_echo(profile, port)
            saved = entry(a)
            edited = {k: v for k, v in saved.items() if k not in ("id", "revision")}
            edited["name"] = "Saved while connected"
            command(
                "otpSave", {"id": a, "revision": saved["revision"], "value": edited}
            )
            command("otpCodes", {"ids": [a, b]})
            command("otpExport", {"ids": [a], "format": "json"})
            check(
                echo("save-code-export") and command("snapshot")["running"] == profile,
                "OTP Save/Code/Export do not interrupt an existing real CONNECT or restart its VPN profile",
            )
            connection.close()
            connection = None
            command("disconnect")
            library, backup_path = saved_state("otp-library")
            check(
                library["version"] == 2
                and len(library["otp"]) == len(list_rows())
                and KEY in backup_path.read_text(),
                "native backup explicitly stores OTP secrets and version2 while retaining the entire ordered library",
            )
            current = entry(a)
            command("otpRemove", {"id": a, "revision": current["revision"]})
            open_backup(backup_path)
            check(
                js(
                    'return Number(document.querySelector("[data-backup-incoming=otp]").textContent)===Number(document.querySelector("[data-backup-current=otp]").textContent)+1'
                )
                and KEY not in js("return document.body.textContent"),
                "backup review compares OTP counts without exposing saved secrets",
            )
            apply_backup()
            check(
                saved_state("restored")[0] == library,
                "backup restore exactly recovers OTP values, IDs, revisions, order and library version",
            )
            click("#backup-undo")
            wait_for('return !!document.querySelector("#backup-confirm")')
            apply_backup()
            check(
                not any(r["id"] == a for r in list_rows()),
                "Previous library undoes OTP backup replacement and restores the prior deletion",
            )
            open_backup(backup_path)
            apply_backup()
            before_reopen = list_rows()
            audit = js(
                "return {calls:window.__otpAudit.calls,safe:window.__otpAudit.safe}"
            )
            check(
                all(privacy(item["value"]) for item in audit["safe"]),
                "observed ordinary RPC responses remain free of OTP secrets throughout edits, exports and backup reviews",
            )

            # Shut down and launch the same saved application in the same private XDG.
            command("saveWindowSettings", {"closeBehavior": "quit"})
            from window_ui import primary

            xconn, window, pid = primary()
            xconn.close()
            js(
                'setTimeout(()=>document.querySelector("[data-window-action=close]").click(),150)'
            )
            deadline = time.monotonic() + 12
            while (
                pathlib.Path("/proc", str(pid)).exists() and time.monotonic() < deadline
            ):
                time.sleep(0.1)
            check(
                not pathlib.Path("/proc", str(pid)).exists(),
                "actual application Close completes after OTP data was committed",
            )
            h["closed_session"] = True
            with contextlib.suppress(RuntimeError):
                h["request"]("DELETE", h["base"])
            created = h["request"](
                "POST",
                "/session",
                {
                    "capabilities": {
                        "alwaysMatch": {
                            "tauri:options": {"application": h["args"].application}
                        }
                    }
                },
            )
            h["session"] = created["sessionId"]
            h["base"] = "/session/" + h["session"]
            h["closed_session"] = False
            wait_for('return !!document.querySelector(".add-connection")')
            settings()
            check(
                list_rows() == before_reopen and command("snapshot")["running"] is None,
                "reopening the real application preserves exact OTP metadata/order and does not start a VPN",
            )
            check(
                entry(a)["counter"] == MAXIMUM
                and command("otpCodes", {"ids": [a]})[0]["code"]
                == expected_code(hotp, 0),
                "persisted secret and i64MAX counter produce the same HOTP after process restart",
            )
            settings("backup")
            open_backup(baseline_path)
            apply_backup()
            check(
                saved_state("baseline-final")[0] == baseline and list_rows() == [],
                "restoring the original version1 baseline removes all synthetic OTP and VPN fixtures exactly",
            )
        finally:
            if connection:
                connection.close()
            with contextlib.suppress(Exception):
                (pathlib.Path(h["args"].artifacts) / "otp-audit.json").write_text(
                    json.dumps(
                        {
                            "calls": audit.get("calls", []),
                            "safeResponseCount": len(audit.get("safe", [])),
                            "syntheticOnly": True,
                        },
                        indent=2,
                    )
                    + "\n"
                )
                if js('return !!document.querySelector("dialog")'):
                    close()
                command("disconnect")
                if original_clipboard is not None:
                    command("writeClipboard", {"text": original_clipboard})
                elif original_image is not None:
                    clipboard = Gtk.Clipboard.get(Gdk.SELECTION_CLIPBOARD)
                    clipboard.set_image(original_image)
                    clipboard.store()
                command("preferences", initial["preferences"])
                h["request"]("POST", h["base"] + "/window/rect", geometry)
            server.shutdown()
            server.server_close()
