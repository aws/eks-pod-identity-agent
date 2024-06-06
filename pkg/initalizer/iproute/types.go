package iproute

import (
	"context"

	"github.com/vishvananda/netlink"
)

type (
	// AgentLinkRetriever fetches the agent's link if it exists
	// otherwise it will try to create one
	AgentLinkRetriever interface {
		CreateOrGetLink(ctx context.Context) (AgentLink, error)
	}

	AgentLink interface {
		SetupForAddrFamily(ctx context.Context, addrFamily AddrFamily) error
		SetupRouteTableForAddrFamily(ctx context.Context, family AddrFamily) error

		BringUp(context.Context) error
		Name() string
	}

	AddrFamily struct {
		// A valid family type, for now we only support AF_INET and AF_INET6
		Family int
		// IP address of that is compatible with Family
		LinkLocalAddr *netlink.Addr
	}
)
