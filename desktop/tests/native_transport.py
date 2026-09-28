"""Recover dropped WebDriver requests with an idempotent operation ticket.

Results stay only in the disposable webview's memory (at most eight receipts).
A session-scoped numeric watermark prevents an old request from executing after
navigation; it contains no arguments, results or application data.
"""
import http.client
import itertools
import json
import time
import urllib.error
import uuid

_sequence = itertools.count(1)
_key = '__thronium_test_' + uuid.uuid4().hex
_LOST = (http.client.RemoteDisconnected, ConnectionResetError, urllib.error.URLError)


def read(raw, method, path, payload=None):
    for attempt in range(4):
        try: return raw(method, path, payload)
        except _LOST:
            if attempt == 3: raise
            time.sleep(.1)


def execute(raw, method, path, payload):
    ticket = next(_sequence)
    head = 'const key=' + json.dumps(_key) + ',id=' + str(ticket) + ''';
const book=window[key]??={latest:Number(sessionStorage.getItem(key)||0),receipts:{}};
let receipt=book.receipts[id];
'''
    if path.endswith('/execute/async'):
        body = head + '''const complete=arguments[arguments.length-1];
if(receipt){if(receipt.done){if(receipt.error)throw new Error(receipt.error);complete(receipt.value);}else{receipt.waiters.push(complete);}return;}
if(id<=book.latest)throw new Error('Expired test operation; it will not execute again');
receipt={id,done:false,waiters:[complete]};book.receipts[id]=receipt;book.latest=id;sessionStorage.setItem(key,String(id));
for(const old of Object.keys(book.receipts))if(Number(old)<=id-8)delete book.receipts[old];
arguments[arguments.length-1]=(value)=>{receipt.value=value??null;receipt.done=true;for(const finish of receipt.waiters){try{finish(value);}catch{}}receipt.waiters=[];};
try {(()=>{''' + payload['script'] + '''})();}catch(error){receipt.error=String(error);receipt.done=true;throw error;}'''
    else:
        body = head + '''if(receipt){if(receipt.error)throw new Error(receipt.error);return receipt.value;}
if(id<=book.latest)throw new Error('Expired test operation; it will not execute again');
receipt={id,done:false};book.receipts[id]=receipt;book.latest=id;sessionStorage.setItem(key,String(id));
for(const old of Object.keys(book.receipts))if(Number(old)<=id-8)delete book.receipts[old];
try {const value=(()=>{''' + payload['script'] + '''})();receipt.value=value??null;receipt.done=true;return value;}catch(error){receipt.error=String(error);receipt.done=true;throw error;}'''
    sync_path = path.rsplit('/execute/', 1)[0] + '/execute/sync'
    lost = None
    for attempt in range(4):
        try: return raw(method, path, {**payload, 'script': body})
        except _LOST as error:
            lost = error
            try:
                receipt = read(raw, 'POST', sync_path, {'script': 'const r=window[arguments[0]]?.receipts[arguments[1]];return r?.done?{value:r.value,failure:r.error??null}:null;', 'args': [_key, ticket]})
                if receipt is not None:
                    if receipt.get('failure'): raise RuntimeError(receipt['failure'])
                    return receipt.get('value')
            except _LOST: pass
            # The same guarded ticket may be submitted again, never the bare mutation.
            time.sleep(.1)
    raise AssertionError('WebDriver completion could not be verified; the operation ticket was never executed twice') from lost


def refresh(raw, method, path, payload):
    sync_path = path.rsplit('/refresh', 1)[0] + '/execute/sync'
    origin = {'script': 'return performance.timeOrigin;', 'args': []}
    before = read(raw, 'POST', sync_path, origin)
    try: return raw(method, path, payload)
    except _LOST as lost:
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            try:
                if read(raw, 'POST', sync_path, origin) != before: return None
            except _LOST: pass
            time.sleep(.1)
        raise AssertionError('WebDriver reload completion could not be verified; navigation was not repeated') from lost
