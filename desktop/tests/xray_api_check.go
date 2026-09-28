// Queries the real loopback gRPC API created by xray-settings-smoke.
package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	stats "github.com/xtls/xray-core/app/stats/command"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func main() {
	conn, err := grpc.NewClient("127.0.0.1:"+os.Args[1], grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		panic(err)
	}
	defer conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client := stats.NewStatsServiceClient(conn)
	if _, err = client.GetSysStats(ctx, &stats.SysStatsRequest{}); err != nil {
		panic(err)
	}
	response, err := client.QueryStats(ctx, &stats.QueryStatsRequest{})
	if err != nil {
		panic(err)
	}
	var inbound, outbound bool
	for _, stat := range response.GetStat() {
		if stat.GetValue() > 0 {
			inbound = inbound || strings.HasPrefix(stat.GetName(), "inbound>>>thronium-in>>>")
			outbound = outbound || strings.HasPrefix(stat.GetName(), "outbound>>>proxy>>>")
		}
	}
	if !inbound || !outbound {
		panic("Xray API did not report actual inbound and outbound traffic")
	}
	fmt.Println("PASS Xray gRPC StatsService returns system statistics and actual traffic counters")
}
