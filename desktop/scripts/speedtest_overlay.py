"""Validate HTTP speed measurements in a private copy of the pinned SDK."""
import hashlib
from pathlib import Path
import shutil
import subprocess

MODULE = 'github.com/Mahdi-zarei/speedtest-go'
PINNED = {
    'speedtest/request.go': 'e0231738ef39ed76f61c64c99159002de75e77038df4278f0de59d4638488874',
    'speedtest/server.go': 'a458f15dd9e86ba9a52ade3e640950a39e2e0e2cfa8389b107e69ab716a78e73',
}


def replace(text, old, new, count=1):
    if text.count(old) != count:
        raise RuntimeError('Pinned speedtest code changed; review HTTP measurement validation')
    return text.replace(old, new)


def prepare(core, directory, modfile, env):
    source = Path(subprocess.check_output(['go', 'list', '-m', '-f', '{{.Dir}}', MODULE], cwd=core, env=env, text=True).strip())
    texts = {}
    for rel, digest in PINNED.items():
        data = (source / rel).read_bytes()
        if hashlib.sha256(data).hexdigest() != digest:
            raise RuntimeError('Pinned speedtest SDK changed; review measurement validation')
        texts[rel] = data.decode()
    text = texts['speedtest/request.go']
    for direction, letter, size in [('Download', 'DL', 3), ('Upload', 'UL', 4)]:
        lower = direction.lower()
        start = text.index('func (s *Server) '+lower+'TestContext(')
        end = text.index('\n}\n', start) + 3
        part = text[start:end]
        part = replace(part, '\t_context, cancel := context.WithCancel(ctx)', '\t_context, cancel := context.WithCancel(ctx)\n\tdefer cancel()\n\tvar failures transferErrors')
        part = replace(part, '\t\t\tatomic.AddInt64(&errorTimes, 1)', '\t\t\tatomic.AddInt64(&errorTimes, 1)\n\t\t\tif failures.record(err) { cancel() }')
        part = replace(part, '}).Start(ctx, cancel, 0)', '}).Start(_context, cancel, 0)')
        part = replace(part, '\treturn nil', '\tif failures.err != nil { return failures.err }\n\treturn validateTransfer("'+lower+'", s.Context.GetTotal'+direction+'(), float64(s.'+letter+'Speed))')
        text = text[:start] + part + text[end:]
    text = replace(text, '\tdefer resp.Body.Close()\n\treturn s.Context.NewChunk().DownloadHandler(resp.Body)', '\tdefer resp.Body.Close()\n\tif err := checkHTTPStatus(resp); err != nil { return err }\n\treturn s.Context.NewChunk().DownloadHandler(resp.Body)')
    text = replace(text, '\t_, _ = io.Copy(io.Discard, resp.Body)\n\tdefer resp.Body.Close()\n\treturn err', '\tdefer resp.Body.Close()\n\tif err := checkHTTPStatus(resp); err != nil { return err }\n\t_, err = io.Copy(io.Discard, resp.Body)\n\treturn err')
    text = replace(text, '\t\t_, _ = io.Copy(io.Discard, resp.Body)\n\t\t_ = resp.Body.Close()', '\t\tstatusErr := checkHTTPStatus(resp)\n\t\t_, bodyErr := io.Copy(io.Discard, resp.Body)\n\t\t_ = resp.Body.Close()\n\t\tif statusErr != nil || bodyErr != nil { failTimes++; continue }')
    texts['speedtest/request.go'] = text
    text = texts['speedtest/server.go']
    text = replace(text, '\t_payloadType := typeJSONPayload', '\tif err := checkHTTPStatus(resp); err != nil { resp.Body.Close(); return Servers{}, err }\n\t_payloadType := typeJSONPayload')
    text = replace(text, '\t\t_payloadType = typeXMLPayload', '\t\tif err := checkHTTPStatus(resp); err != nil { resp.Body.Close(); return Servers{}, err }\n\t\t_payloadType = typeXMLPayload')
    text = replace(text, '\t\tserver.Context = s', '\t\tif server == nil { return nil, errors.New("invalid speedtest server list") }\n\t\tserver.Context = s')
    text = replace(text, 'context.WithTimeout(context.Background(), time.Second*4)', 'context.WithTimeout(ctx, time.Second*4)')
    text = replace(text, '\twg.Wait()\n\tfc()', '\twg.Wait()\n\tfc()\n\tif ctx.Err() != nil { return nil, ctx.Err() }')
    texts['speedtest/server.go'] = text
    module = directory / source.name
    if not module.exists():
        shutil.copytree(source, module)
    outputs = []
    for rel, content in texts.items():
        target = module / rel
        target.chmod(0o644)
        target.write_text(content)
        outputs.append(target)
    (module / 'speedtest').chmod(0o755)
    for helper in sorted((Path(__file__).parent / 'overlays/speedtest').glob('*.go')):
        target = module / 'speedtest' / helper.name
        if target.exists():
            target.chmod(0o644)
        target.write_bytes(helper.read_bytes())
        outputs.append(target)
    subprocess.run(['go', 'mod', 'edit', '-modfile', str(modfile), '-replace='+MODULE+'='+str(module)], cwd=core, env=env, check=True)
    return outputs
