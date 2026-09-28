#!/usr/bin/env python3
"""Use the independently tested private HTTPS fixture; no generated codes printed."""
import json,sys
from pathlib import Path
sys.path.insert(0,str(Path(sys.argv[1]).resolve().parent))
from vpn_otp_fixture import OtpFormServer,certificate_files
root=Path(sys.argv[2]);root.mkdir(parents=True,exist_ok=True)
cert,key=certificate_files(root)
server=OtpFormServer(cert,key,root/'events.jsonl')
try:
    configs={
        'hotp':server.add_case('hotp',kind='hotp',steps=2),
        'login':server.add_case('login',kind='hotp',shape='login'),
        'template':server.add_case('template',kind='hotp',shape='template'),
        'limited':server.add_case('limited',kind='hotp',always_reject=True),
        'totp':server.add_case('totp',kind='totp',period=8,reject_valid=1),
        'invalid':server.add_case('invalid',kind='hotp',shape='unknown'),
    }
    from vpn_auth_fixture import FORM_USER, FORM_PASSWORD
    configs['login'].update({'username':FORM_USER,'password':FORM_PASSWORD,'form_entries':[{'form_id':'login','name':'realm','value':'two'}]})
    configs['template']['form_entries']=[{'name':'custom_challenge','value':'prefix-{otp}-suffix-{otp}'}]
    print(json.dumps(configs),flush=True)
    sys.stdin.read()
finally:
    server.close()
