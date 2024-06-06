package iproute

import (
	"context"
	"fmt"

	"github.com/vishvananda/netlink"
	"go.amzn.com/eks/eks-pod-identity-agent/configuration"
	"go.amzn.com/eks/eks-pod-identity-agent/internal/middleware/logger"
)

type (
	// actual implementation of the interface
	agentLinkRetriever struct {
		netlinkHandle NetlinkHandle
	}
)

func NewAgentLinkRetriever(handle *netlink.Handle) AgentLinkRetriever {
	return &agentLinkRetriever{
		netlinkHandle: handle,
	}
}

func (l *agentLinkRetriever) CreateOrGetLink(ctx context.Context) (AgentLink, error) {
	log := logger.FromContext(ctx)

	attrs := netlink.NewLinkAttrs()
	attrs.Name = configuration.AgentLinkName
	dummyDevice := &netlink.Dummy{LinkAttrs: attrs}

	link, err := l.netlinkHandle.LinkByName(attrs.Name)
	if err != nil {
		_, errWasLinkNotFound := err.(netlink.LinkNotFoundError)
		if !errWasLinkNotFound {
			return nil, fmt.Errorf("error finding %s: %w", attrs.Name, err)
		}

		log.Infof("Link was not found, creating it")
		link, err = l.createLink(ctx, dummyDevice)
		if err != nil {
			return nil, fmt.Errorf("unable to create interface %v: %w", dummyDevice.Name, err)
		}
		log.Debugf("Link %s created", link.Attrs().Name)
	}

	return &agentLink{
		netlinkHandle: l.netlinkHandle,
		link:          link,
	}, nil
}

func (l *agentLinkRetriever) createLink(ctx context.Context, dummyDevice *netlink.Dummy) (netlink.Link, error) {
	log := logger.FromContext(ctx)

	err := l.netlinkHandle.LinkAdd(dummyDevice)
	if err != nil {
		log.Errorf("Unable to create interface %s: %v", dummyDevice.Name, err)
		return nil, err
	}
	return l.netlinkHandle.LinkByName(dummyDevice.Name)
}

type agentLink struct {
	netlinkHandle NetlinkHandle
	link          netlink.Link
}

// SetupForAddrFamily adds the given addr to the interface if its not already
// there (e.g. existing CIDR attached to interface contains the given IP addr)
func (l *agentLink) SetupForAddrFamily(ctx context.Context, addrFamily AddrFamily) error {
	// override ctx with logger with metadata
	log := logger.FromContext(ctx)

	if addrFamily.LinkLocalAddr == nil {
		return fmt.Errorf("family 0x%02x does not specify a link-local addr to bind to", addrFamily.Family)
	}

	isIpAttachedToLink, err := l.isIpAttachedToLink(ctx, addrFamily.Family, addrFamily.LinkLocalAddr)
	if err != nil {
		return err
	}

	if !isIpAttachedToLink {
		log.Infof("Adding IP %s to %v as it was not found on interface", addrFamily.LinkLocalAddr, l.link.Attrs().Name)
		if err = l.addIpToLink(addrFamily.LinkLocalAddr); err != nil {
			return err
		}
	} else {
		log.Infof("Found IP %s on interface %s, continuing", addrFamily.LinkLocalAddr, l.link.Attrs().Name)
	}

	return nil
}

// BringUp is the equivalent of calling `ip link set interface up`
func (l *agentLink) BringUp(ctx context.Context) error {
	// bring up the link if it's not up. Calling "set up" on a link
	// that is already up is a no-op
	log := logger.FromContext(ctx)
	log.Infof("Bringing up link: %s", l.link.Attrs().Name)
	return l.netlinkHandle.LinkSetUp(l.link)
}

func (l *agentLink) Name() string {
	return l.link.Attrs().Name
}

func (l *agentLink) isIpAttachedToLink(ctx context.Context, ipFamily int, linkLocalIp *netlink.Addr) (bool, error) {
	log := logger.FromContext(ctx)

	addrList, err := l.netlinkHandle.AddrList(l.link, ipFamily)
	if err != nil {
		log.Errorf("Unable to read address list: %v", err)
		return false, err
	}

	for _, al := range addrList {
		log.Tracef("Discovered addr %v attached to link %s", al, l.link.Attrs().Name)
		if al.Contains(linkLocalIp.IP) {
			return true, nil
		}
	}

	return false, nil
}

func (l *agentLink) addIpToLink(linkLocalIp *netlink.Addr) error {
	return l.netlinkHandle.AddrAdd(l.link, linkLocalIp)
}
