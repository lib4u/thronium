package api

import (
    "net/http"
    "net/http/httptest"
    "os"
    "path/filepath"
    "strings"
    "testing"
)

func ownedDashboard(t *testing.T) *dashboard {
    t.Helper()
    root := t.TempDir()
    for name, text := range map[string]string{"thronium.html":"owned handoff", "thronium-bootstrap.js":"owned bootstrap", "index.html":"vendor dashboard", "sw.js":"vendor worker"} {
        if err := os.WriteFile(filepath.Join(root,name),[]byte(text),0600); err != nil {t.Fatal(err)}
    }
    return &dashboard{fileServer:http.StripPrefix(dashboardRoutePrefix,http.FileServer(http.Dir(root)))}
}
func TestThroniumBootstrapOutsideWorkerScope(t *testing.T) {
    d:=ownedDashboard(t)
    for path, body:=range map[string]string{"/thronium-dashboard.html":"owned handoff", "/thronium-dashboard.js":"owned bootstrap", "/thronium-dashboard%2Ehtml":"owned handoff"} {
        for _, method:=range []string{http.MethodGet,http.MethodHead} {
            r:=httptest.NewRequest(method,path,nil); original:=r.URL.String();w:=httptest.NewRecorder()
            d.serveHTTP(w,r)
            if w.Code!=200 || strings.HasPrefix(r.URL.Path,dashboardRoutePrefix) || r.URL.String()!=original {t.Fatalf("alias %s: status=%d original=%s result=%s",path,w.Code,original,r.URL)}
            if w.Header().Get("Cache-Control")!="no-store" || w.Header().Get("Referrer-Policy")!="no-referrer" || w.Header().Get("Location")!="" {t.Fatal("handoff must not redirect or cache")}
            if method==http.MethodHead {if w.Body.Len()!=0 {t.Fatal("HEAD returned a body")}} else if w.Body.String()!=body {t.Fatalf("wrong alias response: %q",w.Body.String())}
        }
    }
}
func TestThroniumBootstrapRejectsNonReadMethods(t *testing.T) {
    d:=ownedDashboard(t)
    for _, path:=range []string{"/thronium-dashboard.html","/thronium-dashboard.js"} {
        for _, method:=range []string{http.MethodPost,http.MethodPut,http.MethodDelete} {
            w:=httptest.NewRecorder();d.serveHTTP(w,httptest.NewRequest(method,path,nil))
            if w.Code!=http.StatusMethodNotAllowed || w.Header().Get("Allow")!="GET, HEAD" || w.Body.Len()!=0 {t.Fatalf("unexpected response %d %q",w.Code,w.Body.String())}
        }
    }
}
func TestThroniumBootstrapKeepsVendorRoutesAndDoesNotExposeOtherRootAssets(t *testing.T) {
    d:=ownedDashboard(t)
    for path,body:=range map[string]string{"/dashboard/":"vendor dashboard","/dashboard/sw.js":"vendor worker"} {
        w:=httptest.NewRecorder();d.serveHTTP(w,httptest.NewRequest(http.MethodGet,path,nil));if w.Code!=200 || w.Body.String()!=body {t.Fatalf("vendor route changed: %s %d",path,w.Code)}
    }
    for _,path:=range []string{"/sw.js","/thronium-dashboard.html/extra","/thronium-dashboard.js/../sw.js","/receipt.json"} {
        w:=httptest.NewRecorder();d.serveHTTP(w,httptest.NewRequest(http.MethodGet,path,nil))
        if w.Code!=http.StatusFound || w.Header().Get("Location")!=dashboardRoutePrefix {t.Fatalf("unexpected root alias %s: %d",path,w.Code)}
    }
}
