// Exercise the pinned core's real headless decoder and constructor without I/O.
package main

import (
    "context"
    stdjson "encoding/json"
    "os"

    "github.com/sagernet/sing-box/adapter"
    "github.com/sagernet/sing-box/option"
    "github.com/sagernet/sing-box/route/rule"
    "github.com/sagernet/sing/common/json"
)

type input struct {
    Name string `json:"name"`
    Rules stdjson.RawMessage `json:"rules"`
}

func main() {
    data, err := os.ReadFile(os.Args[1]); if err != nil { panic(err) }
    var cases []input
    if err := stdjson.Unmarshal(data, &cases); err != nil { panic(err) }
    results := []map[string]any{}
    for _, test := range cases {
        source := append([]byte(`{"type":"inline","tag":"fixture","rules":`), test.Rules...)
        source = append(source, '}')
        var set option.RuleSet
        result := map[string]any{"name": test.Name, "decodeAccepted": false, "buildAccepted": false}
        err := json.Unmarshal(source, &set)
        if err == nil {
            result["decodeAccepted"] = true
            result["ruleCount"] = len(set.InlineOptions.Rules)
            normalized, marshalErr := stdjson.Marshal(set.InlineOptions.Rules)
            if marshalErr != nil { panic(marshalErr) }
            result["decodedRules"] = stdjson.RawMessage(normalized)
            matches := []bool{}
            for _, condition := range set.InlineOptions.Rules {
                var built adapter.HeadlessRule
                if built, err = rule.NewHeadlessRule(context.Background(), condition); err != nil { break }
                matches = append(matches, built.Match(&adapter.InboundContext{Network: "tcp"}))
            }
            result["buildAccepted"] = err == nil
            if err == nil { result["tcpMetadataRuleMatches"] = matches }
        }
        if err != nil { result["error"] = err.Error() }
        results = append(results, result)
    }
    encoder := stdjson.NewEncoder(os.Stdout); encoder.SetIndent("", "  ")
    if err := encoder.Encode(results); err != nil { panic(err) }
}
