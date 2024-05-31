package iproute

import (
	"context"
	"fmt"

	"github.com/vishvananda/netlink"
	"go.amzn.com/eks/eks-pod-identity-agent/internal/middleware/logger"
)

func (l *agentLink) SetupRouteTableForAddrFamily(ctx context.Context, family AddrFamily) error {
	log := logger.FromContext(ctx)

	newRoute := &netlink.Route{
		LinkIndex: l.link.Attrs().Index,
		Dst:       family.LinkLocalAddr.IPNet,
	}

	routeList, err := l.netlinkHandle.RouteList(nil, family.Family)
	if err != nil {
		return fmt.Errorf("unable to fetch newRoute list for interface %s: %w", l.link.Attrs().Name, err)
	}

	// search for the newRoute, if it already exists do not create it
	for _, existingRoute := range routeList {
		log.Tracef("Got route: (tbl: %v, dst: %v, iface idx: %v)", existingRoute.Table, existingRoute.Dst, existingRoute.LinkIndex)
		if dstRoutesEq(&existingRoute, newRoute) {
			if err = l.validateRouteLinkMatch(existingRoute); err != nil {
				return err
			}
			log.Infof("Route (dst: %v, iface idx: %v) already exists, skipping creation", existingRoute.Dst, existingRoute.LinkIndex)
			return nil
		} else {
			log.Tracef("Discarding route %v as it doesnt contain %v", existingRoute.Dst, family.LinkLocalAddr.IP)
		}
	}

	err = l.netlinkHandle.RouteAdd(newRoute)
	if err != nil {
		return fmt.Errorf("unable to create route for addr %v: %v", family.LinkLocalAddr, err)
	}
	log.Infof("Created newRoute (dst: %v, iface idx: %v)", newRoute.Dst, newRoute.LinkIndex)

	return nil
}

func (l *agentLink) validateRouteLinkMatch(existingRoute netlink.Route) error {
	if existingRoute.LinkIndex != l.link.Attrs().Index {
		return fmt.Errorf("expected route %s to be interface index %d but is %d, please remove route and try again",
			existingRoute.Dst, l.link.Attrs().Index, existingRoute.LinkIndex)
	}
	return nil
}

func dstRoutesEq(rt1 *netlink.Route, rt2 *netlink.Route) bool {
	return rt1.Dst != nil && rt2.Dst != nil && rt1.Dst.Contains(rt2.Dst.IP) && rt2.Dst.Contains(rt1.Dst.IP)
}
