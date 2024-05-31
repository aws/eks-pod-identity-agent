package iproute

import "github.com/vishvananda/netlink"

//go:generate mockgen.sh iproute $GOFILE

type (
	// NetlinkHandle abstracts the required methods used by the AgentLinkRetriever and AgentLink
	// useful for test purposes
	NetlinkHandle interface {
		LinkByName(name string) (netlink.Link, error)
		LinkAdd(link netlink.Link) error
		LinkSetUp(link netlink.Link) error

		AddrList(link netlink.Link, family int) ([]netlink.Addr, error)
		AddrAdd(link netlink.Link, addr *netlink.Addr) error

		RouteList(link netlink.Link, family int) ([]netlink.Route, error)
		RouteAdd(route *netlink.Route) error
	}
)
