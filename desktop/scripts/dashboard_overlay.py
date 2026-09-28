"""Expose only the connection handoff outside the dashboard Service Worker scope."""
from pathlib import Path


def prepare(source_dir: Path, module: Path):
    source = source_dir / 'service/api/dashboard.go'
    content = source.read_text()
    anchor = 'func (d *dashboard) serveHTTP(writer http.ResponseWriter, request *http.Request) {\n'
    if content.count(anchor) != 1:
        raise RuntimeError('Pinned dashboard handler changed; review connection handoff aliases')
    addition = '''
    // The vendor's /dashboard/ Service Worker may serve its cached index for
    // every navigation in that scope. Keep the credential handoff outside it.
    var bootstrapAsset string
    switch request.URL.Path {
    case "/thronium-dashboard.html": bootstrapAsset = "thronium.html"
    case "/thronium-dashboard.js": bootstrapAsset = "thronium-bootstrap.js"
    }
    if bootstrapAsset != "" {
        if request.Method != http.MethodGet && request.Method != http.MethodHead {
            writer.Header().Set("Allow", "GET, HEAD")
            writer.WriteHeader(http.StatusMethodNotAllowed)
            return
        }
        forwarded := request.Clone(request.Context())
        forwarded.URL.Path = dashboardRoutePrefix + bootstrapAsset
        forwarded.URL.RawPath = ""
        writer.Header().Set("Cache-Control", "no-store")
        writer.Header().Set("Referrer-Policy", "no-referrer")
        d.fileServer.ServeHTTP(writer, forwarded)
        return
    }
'''
    destination = module / 'service/api/dashboard.go'
    destination.chmod(0o644)
    destination.write_text(content.replace(anchor, anchor + addition))
    return [destination]
