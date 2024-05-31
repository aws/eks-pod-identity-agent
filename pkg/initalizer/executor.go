package initalizer

import (
	"context"

	"github.com/vishvananda/netlink"
	"go.amzn.com/eks/eks-pod-identity-agent/configuration"
	"go.amzn.com/eks/eks-pod-identity-agent/internal/middleware/logger"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/initalizer/iproute"
	"golang.org/x/sys/unix"
)

// An Executor orchestrates the creation of the agent net link
// and configuration of the route table in both IPv4 & IPv6
type Executor struct {
	agentLinkRetriever iproute.AgentLinkRetriever
}

func NewExecutor() (*Executor, error) {
	handle, err := netlink.NewHandle()
	if err != nil {
		return nil, err
	}

	return &Executor{
		agentLinkRetriever: iproute.NewAgentLinkRetriever(handle),
	}, nil
}

func (e *Executor) Initialize(ctx context.Context) error {
	log := logger.FromContext(ctx)

	ipv4LinkLocalAddr, err := netlink.ParseAddr(configuration.DefaultIpv4TargetHost + "/32")
	if err != nil {
		panic(err)
	}

	ipv6LinkLocalAddr, err := netlink.ParseAddr(configuration.DefaultIpv6TargetHost + "/128")
	if err != nil {
		panic(err)
	}

	// first create the interface
	link, err := e.agentLinkRetriever.CreateOrGetLink(ctx)
	if err != nil {
		log.Errorf("Cannot setup link: %v", err)
		return err
	}

	ctx = logger.ContextWithField(ctx, "link", link.Name())
	supportedFamilies := []iproute.AddrFamily{
		{
			Family:        unix.AF_INET,
			LinkLocalAddr: ipv4LinkLocalAddr,
		},
		{
			Family:        unix.AF_INET6,
			LinkLocalAddr: ipv6LinkLocalAddr,
		},
	}

	// attach the required ip addresses to the interface before bringing it up
	for _, fam := range supportedFamilies {
		ctx := logger.ContextWithField(ctx, "ip", fam.LinkLocalAddr)

		err := link.SetupForAddrFamily(ctx, fam)
		if err != nil {
			if isOptionalFamily(fam.Family) {
				// swallow the error if the family we are trying to associate is optional
				log.Errorf("Unable to configure family %02x: %v", fam, err)
			} else {
				log.Fatalf("Stopping execution, unable to configure required family %02x: %v", fam, err)
			}
		}
	}

	// bring the interface up
	err = link.BringUp(ctx)
	if err != nil {
		log.Errorf("Error bringing up link: %v", err)
		return err
	}

	// add the routes to the interface to the default routing table
	for _, fam := range supportedFamilies {
		ctx := logger.ContextWithField(ctx, "ip", fam.LinkLocalAddr)

		err := link.SetupRouteTableForAddrFamily(ctx, fam)
		if err != nil {
			if isOptionalFamily(fam.Family) {
				log.Errorf("Unable to configure family %02x: %v", fam, err)
			} else {
				log.Fatalf("Stopping execution, unable to configure required family %02x: %v", fam, err)
			}
		}
	}

	return nil
}

func isOptionalFamily(fam int) bool {
	return unix.AF_INET6 == fam
}
