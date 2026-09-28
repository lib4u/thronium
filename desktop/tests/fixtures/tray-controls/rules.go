// Generate an entirely synthetic rule set with the repository's pinned sing-box.
// Run from core/server: go run ../../desktop/tests/fixtures/tray-controls/rules.go
package main

import (
    "encoding/json"
    "os"
    "github.com/sagernet/sing-box/common/srs"
    "github.com/sagernet/sing-box/option"
)
func main() {
    var rules option.PlainRuleSetCompat
    if err := json.Unmarshal([]byte(`{"version":1,"rules":[{"ip_cidr":["127.0.0.1/32"]}]}`), &rules); err != nil { panic(err) }
    if err := srs.Write(os.Stdout, rules.Options, 1); err != nil { panic(err) }
}
