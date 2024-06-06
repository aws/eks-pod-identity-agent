//go:build !linux

package iproute

import (
	"context"

	"github.com/vishvananda/netlink"
)

func (l *agentLink) SetupRouteTableForAddrFamily(ctx context.Context, family AddrFamily) error {
	return netlink.ErrNotImplemented
}
