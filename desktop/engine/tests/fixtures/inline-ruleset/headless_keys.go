// Independent schema reflection from the pinned core, not the UI catalogue.
package main

import (
    "encoding/json"
    "os"
    "reflect"
    "sort"
    "strings"

    "github.com/miekg/dns"
    "github.com/sagernet/sing-box/option"
)

func fields(t reflect.Type) []string {
    result := []string{}
    for i := 0; i < t.NumField(); i++ {
        key := strings.Split(t.Field(i).Tag.Get("json"), ",")[0]
        if key != "" && key != "-" { result = append(result, key) }
    }
    sort.Strings(result)
    return result
}

func difference(left, right []string) []string {
    excluded := map[string]bool{}
    for _, key := range right { excluded[key] = true }
    result := []string{}
    for _, key := range left { if !excluded[key] { result = append(result, key) } }
    return result
}

func main() {
    headless := fields(reflect.TypeFor[option.DefaultHeadlessRule]())
    route := fields(reflect.TypeFor[option.RawDefaultRule]())
    result := map[string]any{
        "module": "v1.11.16-0.20260909122315-b801a09c9742",
        "defaultHeadless": headless,
        "logicalHeadless": fields(reflect.TypeFor[option.LogicalHeadlessRule]()),
        "headlessOnlyVsRoute": difference(headless, route),
        "routeOnlyNotHeadless": difference(route, headless),
        "typeDiscriminator": []string{"", "default", "logical"},
        "source": "option/rule_set.go; generated using reflected JSON tags, excluding binary-only fields",
        "dnsQueryTypeNames": dns.StringToType,
    }
    encoder := json.NewEncoder(os.Stdout)
    encoder.SetIndent("", "  ")
    if err := encoder.Encode(result); err != nil { panic(err) }
}
