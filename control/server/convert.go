package server

import (
	"time"

	"github.com/freco-dev/cc01/control/registry"
	cc01v1 "github.com/freco-dev/cc01/proto/gen/cc01/v1"
)

// toProtoMap NetworkMap ni simda yuboriladigan ko'rinishga aylantiradi.
func toProtoMap(netmap *registry.NetworkMap) *cc01v1.WatchNetworkMapResponse {
	out := &cc01v1.WatchNetworkMapResponse{
		Tenant:      netmap.Tenant,
		Version:     netmap.Version,
		Self:        toProtoNode(netmap.Self),
		Full:        netmap.Full,
		Removed:     netmap.Removed,
		GeneratedAt: netmap.GeneratedAt.Unix(),
	}

	out.Peers = make([]*cc01v1.Node, 0, len(netmap.Peers))
	for _, peer := range netmap.Peers {
		out.Peers = append(out.Peers, toProtoNode(peer))
	}

	out.Relays = make([]*cc01v1.Relay, 0, len(netmap.Relays))
	for _, node := range netmap.Relays {
		out.Relays = append(out.Relays, toProtoRelay(node))
	}

	return out
}

func toProtoRelay(node registry.Relay) *cc01v1.Relay {
	return &cc01v1.Relay{
		Id:        node.ID,
		PublicKey: node.PublicKey[:],
		Endpoint:  node.Endpoint.String(),
		Region:    node.Region,
		Priority:  node.Priority,
	}
}

func toProtoNode(node *registry.Node) *cc01v1.Node {
	if node == nil {
		return nil
	}

	out := &cc01v1.Node{
		NodeId:    node.ID,
		PublicKey: node.PublicKey[:],
		Hostname:  node.Hostname,
		Tags:      node.Tags,
		RelayHome: node.RelayHome,
		LastSeen:  node.LastSeen.Unix(),
		Online:    node.Online(time.Now()),
	}

	out.Addresses = make([]string, 0, len(node.Addresses))
	for _, prefix := range node.Addresses {
		out.Addresses = append(out.Addresses, prefix.String())
	}

	out.Endpoints = make([]string, 0, len(node.Endpoints))
	for _, endpoint := range node.Endpoints {
		out.Endpoints = append(out.Endpoints, endpoint.String())
	}

	return out
}
