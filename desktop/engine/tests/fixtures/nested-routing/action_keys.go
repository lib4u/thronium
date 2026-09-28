// Independent reflection of the pinned core's exported option types.
package main

import (
    "encoding/json"
    "os"
    "reflect"
    "sort"
    "strings"

    "github.com/sagernet/sing-box/option"
)

func fields(types ...reflect.Type) []string {
    result := map[string]bool{}
    var visit func(reflect.Type)
    visit = func(t reflect.Type) {
        for t.Kind() == reflect.Pointer { t = t.Elem() }
        if t.Kind() != reflect.Struct { return }
        for i:=0; i<t.NumField(); i++ {
            field:=t.Field(i)
            tag:=strings.Split(field.Tag.Get("json"),",")[0]
            if tag=="-" {continue}
            if field.Anonymous && tag=="" {visit(field.Type);continue}
            if tag=="" {tag=field.Name}
            result[tag]=true
        }
    }
    for _,t:=range types {visit(t)}
    values:=[]string{}
    for name:=range result {values=append(values,name)}
    sort.Strings(values)
    return values
}

func main() {
    groups:=map[string][]string{
        "match":fields(reflect.TypeFor[option.RawDefaultRule]()),
        "route":fields(reflect.TypeFor[option.RouteActionOptions]()),
        "route-options":fields(reflect.TypeFor[option.RouteOptionsActionOptions]()),
        "direct":fields(reflect.TypeFor[option.DirectActionOptions]()),
        "reject":fields(reflect.TypeFor[option.RejectActionOptions]()),
        "sniff":fields(reflect.TypeFor[option.RouteActionSniff]()),
        "resolve":fields(reflect.TypeFor[option.RouteActionResolve]()),
    }
    groups["bypass"]=groups["route"]
    groups["hijack-dns"]=[]string{}
    groups["nestedPresenceGuard"]=append([]string{"action"},groups["route"]...)
    matches:=map[string]bool{}
    for _,key:=range groups["match"] {matches[key]=true}
    actions:=map[string]bool{"action":true}
    for _,name:=range []string{"route","route-options","direct","reject","sniff","resolve"} {
        for _,key:=range groups[name] {actions[key]=true}
    }
    groups["actionKeysUnion"]=[]string{}
    groups["overlapMatchAndAction"]=[]string{}
    for key:=range actions {
        groups["actionKeysUnion"]=append(groups["actionKeysUnion"],key)
        if matches[key] {groups["overlapMatchAndAction"]=append(groups["overlapMatchAndAction"],key)}
    }
    for _,values:=range groups {sort.Strings(values)}
    encoder:=json.NewEncoder(os.Stdout);encoder.SetIndent("","  ")
    if err:=encoder.Encode(groups);err!=nil {panic(err)}
}
