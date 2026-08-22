package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	cc01v1 "github.com/freco-dev/cc01/proto/gen/cc01/v1"
)

func runPeer(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("%w: `cc01 peer list` deb yozing", flag.ErrHelp)
	}

	switch args[0] {
	case "list":
		return runPeerList(args[1:])
	default:
		return fmt.Errorf("%w: noma'lum ichki buyruq: %s", flag.ErrHelp, args[0])
	}
}

func runPeerList(args []string) error {
	set := flag.NewFlagSet("peer list", flag.ContinueOnError)
	socket := socketFlag(set)
	asJSON := set.Bool("json", false, "JSON chiqarish")
	onlineOnly := set.Bool("online", false, "faqat sessiyasi bor peerlar")

	if err := set.Parse(args); err != nil {
		return err
	}

	client, closer, err := connect(*socket)
	if err != nil {
		return err
	}
	defer closer()

	response, err := client.Peers(context.Background(), &cc01v1.PeersRequest{
		OnlineOnly: *onlineOnly,
	})
	if err != nil {
		return err
	}

	if *asJSON {
		return emitJSON(response)
	}

	return printPeers(response.GetPeers())
}

func printPeers(peers []*cc01v1.PeerStatus) error {
	if len(peers) == 0 {
		fmt.Println("peer yo'q")
		return nil
	}

	out := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(out, "NODE\tHOSTNAME\tMANZIL\tYO'L\tHOLAT\tRTT\tENDPOINT")

	for _, peer := range peers {
		fmt.Fprintf(out, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			shorten(peer.GetNodeId(), 12),
			orDash(peer.GetHostname()),
			orDash(strings.Join(peer.GetAddresses(), ",")),
			pathLabel(peer),
			peer.GetPathState(),
			formatRTT(peer.GetRttMicros()),
			orDash(peer.GetEndpoint()),
		)
	}

	return out.Flush()
}

// pathLabel yo'lni ko'rsatadi, offline peerlarni ajratib.
func pathLabel(peer *cc01v1.PeerStatus) string {
	if !peer.GetOnline() {
		return "offline"
	}
	return peer.GetPath()
}

func formatRTT(micros uint64) string {
	if micros == 0 {
		return "—"
	}

	d := time.Duration(micros) * time.Microsecond
	if d < time.Millisecond {
		return fmt.Sprintf("%.2fms", d.Seconds()*1000)
	}
	return fmt.Sprintf("%.1fms", d.Seconds()*1000)
}

func orDash(value string) string {
	if value == "" {
		return "—"
	}
	return value
}
