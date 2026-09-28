"""Prevent replay of initial OTP credentials in the pinned OpenVPN client."""
import hashlib
from pathlib import Path
import shutil
import subprocess

MODULE = 'github.com/sagernet/sing-openvpn'
PINNED = {
    'client.go': 'c5165709df48870ec34bb52814a8482cf9249ee02e73b53ccd06eb6e67dd1de8',
    'options.go': '7b594cced37207046febbf85a2e931b67f1a0a724a03e64623cc2696e8f608d1',
    'client_session_tls.go': 'a7dbeba135277d06befaf7ebeddfcde50bc6b3246c5e7ea0074ae211ac23d431',
}


def replace(text, old, new):
    if text.count(old) != 1:
        raise RuntimeError('Pinned OpenVPN code changed; review single-use credentials')
    return text.replace(old, new)


def prepare(core, directory, modfile, env, box_source, box_module):
    source = Path(subprocess.check_output(['go', 'list', '-m', '-f', '{{.Dir}}', MODULE], cwd=core, env=env, text=True).strip())
    texts = {}
    for name, digest in PINNED.items():
        data = (source / name).read_bytes()
        if hashlib.sha256(data).hexdigest() != digest:
            raise RuntimeError('Pinned OpenVPN source changed; review single-use credentials')
        texts[name] = data.decode()
    texts['client.go'] = replace(texts['client.go'], '\tstaged                      stagedCredentials', '\tsingleUseSent               bool\n\tstaged                      stagedCredentials')
    texts['options.go'] = replace(texts['options.go'], 'type ClientAuthenticationOptions struct {', 'type ClientAuthenticationOptions struct {\n\tSingleUse bool')
    for old, result in [('c.useActiveAuthToken', 'err'), ('true', 'nil, err')]:
        pattern = '\tusername, password := c.parent.sessionCredentials(' + old + ')'
        texts['client_session_tls.go'] = replace(texts['client_session_tls.go'], pattern,
            '\tif err := c.parent.reserveSingleUseAuth(); err != nil { return ' + result + ' }\n' + pattern)
    module = directory / source.name
    if not module.exists():
        shutil.copytree(source, module)
    outputs = []
    for name, content in texts.items():
        target = module / name
        target.chmod(0o644)
        target.write_text(content)
        outputs.append(target)
    module.chmod(0o755)
    for helper in sorted((Path(__file__).parent / 'overlays/openvpn').glob('*.go')):
        target = module / helper.name
        if target.exists():
            target.chmod(0o644)
        target.write_bytes(helper.read_bytes())
        outputs.append(target)
    for name, patches in {
        'option/openvpn.go': [('AuthRetry            string', 'SingleUseAuth bool `json:"single_use_auth,omitempty"`\n\tAuthRetry            string')],
        'protocol/openvpn/client.go': [
            ('AuthRetry:           options.AuthRetry,', 'AuthRetry:           options.AuthRetry,\n\t\t\tSingleUse: options.SingleUseAuth,'),
            ('if options.Username != "" || options.Password != "" || (options.AuthRetry', 'if options.SingleUseAuth || options.Username != "" || options.Password != "" || (options.AuthRetry'),
        ],
    }.items():
        content = (box_source / name).read_text()
        for old, new in patches:
            content = replace(content, old, new)
        target = box_module / name
        target.parent.chmod(0o755)
        target.chmod(0o644)
        target.write_text(content)
        outputs.append(target)
    subprocess.run(['gofmt', '-w', *map(str, outputs)], check=True, env=env)
    subprocess.run(['go', 'mod', 'edit', '-modfile', str(modfile), '-replace='+MODULE+'='+str(module)], cwd=core, env=env, check=True)
    return outputs
