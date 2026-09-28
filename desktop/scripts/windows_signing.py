#!/usr/bin/env python3
"""Authenticode signing for the Windows build, taken from the environment.

Unset, the build stays unsigned (a test build: SmartScreen warns about it).
One of two ways:

- THRONIUM_SIGN_COMMAND: a command with %1 for the file, run for every binary
  Tauri signs (the application, the core, the installer and its
  uninstaller). For Azure Trusted Signing:
  `trusted-signing-cli -e <endpoint> -a <account> -c <profile> -d Thronium %1`
  with AZURE_CLIENT_ID, AZURE_CLIENT_SECRET and AZURE_TENANT_ID set.
- THRONIUM_SIGN_THUMBPRINT: the SHA-1 thumbprint of a certificate in the
  current user's store (an OV certificate on a hardware token or in a cloud
  HSM through its CSP), signed by signtool with THRONIUM_SIGN_TIMESTAMP
  (default DigiCert's RFC 3161 server).

`python3 scripts/windows_signing.py` prints the Tauri configuration it adds.
"""
import json
import os
import pathlib
import re

DEFAULT_TIMESTAMP = 'http://timestamp.digicert.com'


def config(environ=os.environ):
    """The Tauri configuration to merge for signing, or None for none."""
    command = environ.get('THRONIUM_SIGN_COMMAND', '').strip()
    thumbprint = environ.get('THRONIUM_SIGN_THUMBPRINT', '').strip().replace(' ', '')
    if command and thumbprint:
        raise SystemExit('Set THRONIUM_SIGN_COMMAND or THRONIUM_SIGN_THUMBPRINT, not both')
    if command:
        if '%1' not in command:
            raise SystemExit('THRONIUM_SIGN_COMMAND must name the file as %1')
        windows = {'signCommand': command}
    elif thumbprint:
        if not re.fullmatch(r'[0-9A-Fa-f]{40}', thumbprint):
            raise SystemExit('THRONIUM_SIGN_THUMBPRINT must be a 40-digit SHA-1 thumbprint')
        timestamp = environ.get('THRONIUM_SIGN_TIMESTAMP', DEFAULT_TIMESTAMP)
        windows = {'certificateThumbprint': thumbprint, 'digestAlgorithm': 'sha256',
                   'timestampUrl': timestamp, 'tsp': True}
    else:
        return None
    return {'bundle': {'windows': windows}}


def tauri_arguments(directory, environ=os.environ):
    """Arguments for `tauri build` that turn signing on, if it is configured.
    The configuration goes through a file in directory: on Windows `npx` runs
    through the shell, which would take a JSON argument apart."""
    merged = config(environ)
    if not merged:
        return []
    path = pathlib.Path(directory) / 'signing.tauri.json'
    path.write_text(json.dumps(merged, indent=2) + '\n')
    return ['--config', str(path)]


if __name__ == '__main__':
    print(json.dumps(config(), indent=2))
