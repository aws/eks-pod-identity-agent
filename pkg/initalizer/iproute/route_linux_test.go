package iproute

import (
	"context"
	"fmt"
	"net"
	"testing"

	. "github.com/onsi/gomega"
	"github.com/vishvananda/netlink"
	"go.amzn.com/eks/eks-pod-identity-agent/configuration"
	_ "go.amzn.com/eks/eks-pod-identity-agent/internal/test"
	"go.uber.org/mock/gomock"
)

func TestAgentLink_SetupRouteTableForAddrFamily(t *testing.T) {
	var (
		linkIdx   = 1
		attrs     = netlink.LinkAttrs{Name: configuration.AgentLinkName, Index: linkIdx}
		dummyLink = &netlink.Dummy{LinkAttrs: attrs}

		_, targetIp, _ = net.ParseCIDR("192.168.1.5/32")
		targetAddr     = &netlink.Addr{
			IPNet: targetIp,
		}
		targetAddrFamily = AddrFamily{
			LinkLocalAddr: targetAddr,
			Family:        1,
		}

		expectedRoute = netlink.Route{LinkIndex: linkIdx, Dst: targetIp}
		invalidRoute  = netlink.Route{LinkIndex: 2, Dst: targetIp}

		_, otherIp, _ = net.ParseCIDR("192.168.1.3/32")
		otherRouteDst = netlink.Route{LinkIndex: 3, Dst: otherIp}
		otherRouteGw  = netlink.Route{LinkIndex: 3, Gw: otherIp.IP}

		_, cidrOverlapWithTargetIp, _ = net.ParseCIDR("192.168.1.3/24")
		cidrOverlapRouteCidr          = netlink.Route{LinkIndex: 2, Dst: cidrOverlapWithTargetIp}
	)

	testCases := []struct {
		name        string
		handleCalls func(handle *MockNetlinkHandle)
		addrFamily  AddrFamily
		error       error
	}{
		{
			name: "creates a route if there are no routes in default table",
			handleCalls: func(handle *MockNetlinkHandle) {
				gomock.InOrder(
					handle.EXPECT().RouteList(nil, 1).
						Return(nil, nil),
					handle.EXPECT().RouteAdd(gomock.Any()).
						Return(nil),
				)
			},
			addrFamily: targetAddrFamily,
		},
		{
			name: "creates a route if there are some routes that don't match in route table",
			handleCalls: func(handle *MockNetlinkHandle) {
				gomock.InOrder(
					handle.EXPECT().RouteList(nil, 1).
						Return([]netlink.Route{otherRouteDst, otherRouteGw}, nil),
					handle.EXPECT().RouteAdd(gomock.Any()).
						Return(nil),
				)
			},
			addrFamily: targetAddrFamily,
		},
		{
			name: "errors out if route is already assigned to other interface",
			handleCalls: func(handle *MockNetlinkHandle) {
				gomock.InOrder(
					handle.EXPECT().RouteList(nil, 1).
						Return([]netlink.Route{invalidRoute}, nil),
				)
			},
			addrFamily: targetAddrFamily,
			error:      fmt.Errorf("expected route 192.168.1.5/32 to be interface index 1 but is 2, please remove route and try again"),
		},
		{
			name: "creates a route even if there is another device that encapsulates the cidr",
			handleCalls: func(handle *MockNetlinkHandle) {
				gomock.InOrder(
					handle.EXPECT().RouteList(nil, 1).
						Return([]netlink.Route{cidrOverlapRouteCidr}, nil),
					handle.EXPECT().RouteAdd(gomock.Any()).
						Return(nil),
				)
			},
			addrFamily: targetAddrFamily,
		},
		{
			name: "doesn't create the route if it exists",
			handleCalls: func(handle *MockNetlinkHandle) {
				gomock.InOrder(
					handle.EXPECT().RouteList(nil, 1).
						Return([]netlink.Route{expectedRoute}, nil),
				)
			},
			addrFamily: targetAddrFamily,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			g := NewWithT(t)
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			// setup
			handle := NewMockNetlinkHandle(ctrl)
			if tc.handleCalls != nil {
				tc.handleCalls(handle)
			}

			al := &agentLink{
				link:          dummyLink,
				netlinkHandle: handle,
			}
			ctx := context.Background()

			// trigger
			err := al.SetupRouteTableForAddrFamily(ctx, tc.addrFamily)

			// validate
			if tc.error != nil {
				g.Expect(err).To(MatchError(tc.error))
			} else {
				g.Expect(err).ToNot(HaveOccurred())
			}
		})
	}
}
