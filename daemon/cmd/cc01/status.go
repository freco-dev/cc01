package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	cc01v1 "github.com/freco-dev/cc01/proto/gen/cc01/v1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

func runStatus(args []string) error {
	set := flag.NewFlagSet("status", flag.ContinueOnError)
	socket := socketFlag(set)
	asJSON := set.Bool("json", false, "JSON chiqarish")
	watch := set.Bool("watch", false, "real vaqtda kuzatish")

	if err := set.Parse(args); err != nil {
		return err
	}

	client, closer, err := connect(*socket)
	if err != nil {
		return err
	}
	defer closer()

	if *watch {
		return watchStatus(client, *asJSON)
	}

	response, err := client.Status(context.Background(), &cc01v1.StatusRequest{})
	if err != nil {
		return err
	}

	return printStatus(response, *asJSON)
}

func watchStatus(client cc01v1.DaemonServiceClient, asJSON bool) error {
	stream, err := client.WatchStatus(context.Background(), &cc01v1.WatchStatusRequest{})
	if err != nil {
		return err
	}

	for {
		update, err := stream.Recv()
		if err != nil {
			return err
		}

		if !asJSON {
			// Terminalni tozalab, ustiga yozamiz — TUI'ga o'xshash
			// ko'rinish uchun.
			fmt.Print("\033[H\033[2J")
		}
		if err := printStatus(update.GetStatus(), asJSON); err != nil {
			return err
		}
	}
}

func printStatus(status *cc01v1.StatusResponse, asJSON bool) error {
	if asJSON {
		return emitJSON(status)
	}

	if !status.GetConnected() {
		fmt.Println("holat: ulanmagan")
		return nil
	}

	rows := [][2]string{
		{"holat", "ulangan"},
		{"node", shorten(status.GetNodeId(), 16)},
		{"hostname", status.GetHostname()},
		{"manzil", status.GetAddress()},
		{"interfeys", fmt.Sprintf("%s (udp/%d)", status.GetInterface(), status.GetListenPort())},
		{"tenant", status.GetTenant()},
	}

	if cp := status.GetControlPlane(); cp != "" {
		rows = append(rows, [2]string{"control plane", cp})
	}
	if relay := status.GetRelayId(); relay != "" {
		rows = append(rows, [2]string{"relay", relay})
	}
	if endpoints := status.GetEndpoints(); len(endpoints) > 0 {
		rows = append(rows, [2]string{"endpointlar", strings.Join(endpoints, ", ")})
	}

	rows = append(rows,
		[2]string{"peerlar", fmt.Sprint(status.GetPeerCount())},
		[2]string{"ishlash vaqti", formatDuration(time.Duration(status.GetUptimeSeconds()) * time.Second)},
	)

	for _, row := range rows {
		fmt.Printf("  %-16s %s\n", row[0], row[1])
	}

	return nil
}

// emitJSON protobuf xabarini JSON sifatida chiqaradi.
//
// protojson ishlatiladi, encoding/json emas: u proto maydon
// nomlarini va enum qiymatlarini to'g'ri beradi.
func emitJSON(message proto.Message) error {
	encoded, err := protojson.MarshalOptions{
		Multiline:       true,
		Indent:          "  ",
		EmitUnpopulated: true,
	}.Marshal(message)
	if err != nil {
		return err
	}

	_, err = fmt.Fprintln(os.Stdout, string(encoded))
	return err
}

func shorten(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	return value[:limit] + "…"
}

// formatDuration muddatni odam o'qiydigan shaklda beradi.
func formatDuration(d time.Duration) string {
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm %ds", int(d.Minutes()), int(d.Seconds())%60)
	default:
		return fmt.Sprintf("%dh %dm", int(d.Hours()), int(d.Minutes())%60)
	}
}
