package test_utils

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"ThroneCore/internal/boxbox"

	"github.com/sagernet/sing-box/adapter"
)

type IPInfo struct {
	IP          string `json:"ip"`
	CountryCode string `json:"country_code"`
}

var IPReporter resultBuffer[IPTestResult]

const IPTestTimeout = 3 * time.Second
const ipInfoAPI = "https://api.ip2location.io/"

type IPTestResult struct {
	Result IPInfo
	Tag    string
	Error  error
}

func BatchIPTest(ctx context.Context, i *boxbox.Box, outboundTags []string, maxConcurrency int, timeout time.Duration) []*IPTestResult {
	if timeout <= 0 {
		timeout = IPTestTimeout
	}

	results := runBatch(ctx, i, outboundTags, maxConcurrency, batchProbe[IPTestResult]{
		run: func(ctx context.Context, tag string, outbound adapter.Outbound) *IPTestResult {
			client := outboundHTTPClient(ctx, outbound, timeout)
			info, err := ipTest(ctx, client)
			return &IPTestResult{Result: info, Tag: tag, Error: err}
		},
		fail: func(tag string, err error) *IPTestResult {
			return &IPTestResult{Tag: tag, Error: err}
		},
		publish: IPReporter.AddResult,
	})
	IPReporter.Reclaim(results)
	return results
}

func ipTest(ctx context.Context, client *http.Client) (IPInfo, error) {
	var res IPInfo
	req, err := http.NewRequestWithContext(ctx, "GET", ipInfoAPI, nil)
	if err != nil {
		return res, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return res, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return res, errors.New("IP lookup HTTP error")
	}
	const limit = 64 << 10
	data, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return res, err
	}
	if len(data) > limit {
		return res, errors.New("IP lookup response too large")
	}
	err = json.Unmarshal(data, &res)
	if err != nil {
		return res, err
	}
	if net.ParseIP(res.IP) == nil {
		return IPInfo{}, errors.New("invalid IP lookup response")
	}
	res.CountryCode = strings.ToUpper(res.CountryCode)
	if res.CountryCode == "-" {
		res.CountryCode = ""
	}
	if res.CountryCode != "" && (len(res.CountryCode) != 2 || res.CountryCode[0] < 'A' || res.CountryCode[0] > 'Z' || res.CountryCode[1] < 'A' || res.CountryCode[1] > 'Z') {
		return IPInfo{}, errors.New("invalid IP lookup country")
	}
	return res, nil
}
