"""The library at rest with a real Secret Service on the session bus: the file
holds none of the profile's own values in the open, the window says so, and the
rollback copy is written the same way. All values are synthetic."""
import json
import pathlib

SECRET = 'synthetic-sealed-password'


def run(h):
    command, click, wait_for, js, check, screenshot = (
        h[k] for k in ('command', 'click', 'wait_for', 'js', 'check', 'screenshot'))
    initial = command('snapshot')
    root = pathlib.Path(command('storageLocation')['directory'])
    library = root / 'library.json'
    rollback = root / 'backup-before-restore.json'

    def settings_section(section):
        click('.primary-nav button:nth-child(5)')
        wait_for('return !!document.querySelector("[data-settings-section=' + section + ']")')
        click('[data-settings-section=' + section + ']')

    def sealed(path):
        return path.is_file() and path.read_bytes().startswith(b'THRONIUM-SEALED-1\n')

    profile = None
    try:
        command('preferences', {**initial['preferences'], 'language': 'en', 'theme': 'dark'})
        wait_for('return document.documentElement.lang==="en"')
        check(command('snapshot')['sealing'] == 'sealed',
              'a desktop with a key store seals what this installation writes')
        profile = command('saveProfile', {'name': 'Sealed server', 'groupId': 'personal',
                                          'kind': 'sing-box-outbound',
                                          'config': {'type': 'socks', 'server': '192.0.2.77',
                                                     'server_port': 1080,
                                                     'password': SECRET}})['id']
        wait_for('return true')
        check(sealed(library), 'the library on disk is written sealed')
        bytes_on_disk = library.read_bytes()
        for value in (SECRET, 'Sealed server', '192.0.2.77'):
            check(value.encode() not in bytes_on_disk,
                  'nothing of the profile is readable in the file: ' + value)
        # The running application still reads its own library.
        check(command('profile', {'id': profile})['config']['password'] == SECRET,
              'the application reads back what it sealed')

        settings_section('system')
        wait_for('return !!document.querySelector("#storage-sealing")')
        check(js('return document.querySelector("#storage-sealing").dataset.storageSealing') == 'sealed'
              and 'keyring' in js('return document.querySelector("#storage-sealing").textContent'),
              'the settings view states that the library is sealed by the desktop keyring')
        screenshot('secrets-storage-en')
        command('preferences', {**command('snapshot')['preferences'], 'language': 'ru'})
        wait_for('return document.documentElement.lang==="ru"')
        check('связк' in js('return document.querySelector("#storage-sealing").textContent'),
              'the same statement is shown in Russian')
        screenshot('secrets-storage-ru')
        command('preferences', {**command('snapshot')['preferences'], 'language': 'en'})
        wait_for('return document.documentElement.lang==="en"')

        # A restore writes the rollback copy, which is sealed the same way.
        settings_section('backup')
        wait_for('return !!document.querySelector("#backup-save")')
        export = root / 'sealed-export.json'
        from native_dialogs import file_dialog
        click('#backup-save')
        file_dialog('Save backup', export)
        wait_for('return !!document.querySelector("#backup-notice") && !document.querySelector("#backup-save").disabled')
        check(export.is_file() and SECRET in export.read_text(),
              'a backup the user saves where they chose stays a portable file they can read')
        click('#backup-open')
        file_dialog('Open backup', export, opening=True)
        wait_for('return !!document.querySelector("#backup-confirm")')
        click('#backup-acknowledge')
        click('#backup-confirm')
        wait_for('return !document.querySelector("dialog[open]") && !!document.querySelector("#backup-notice")')
        check(sealed(rollback), 'the rollback copy of the library is sealed as well')
        check(SECRET.encode() not in rollback.read_bytes(),
              'the rollback copy holds none of the profile values in the open')
        check(command('snapshot')['sealing'] == 'sealed' and sealed(library),
              'the library stays sealed after a restore')
        (h['artifacts'] / 'secrets-state.json').write_text(json.dumps(
            {'sealing': command('snapshot')['sealing'],
             'librarySealed': sealed(library), 'rollbackSealed': sealed(rollback)}, indent=2) + '\n')
    finally:
        if profile:
            with __import__('contextlib').suppress(Exception):
                command('deleteProfiles', {'ids': [profile]})
        command('preferences', initial['preferences'])
