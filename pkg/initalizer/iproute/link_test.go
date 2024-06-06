package iproute

import (
	"context"
	"fmt"
	"net"
	"testing"

	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/assert"
	"github.com/vishvananda/netlink"
	"go.amzn.com/eks/eks-pod-identity-agent/configuration"
	_ "go.amzn.com/eks/eks-pod-identity-agent/internal/test"
	"go.uber.org/mock/gomock"
)

func TestAgentLinkRetriever_CreateOrGetLink(t *testing.T) {
	var (
		attrs     = netlink.LinkAttrs{Name: configuration.AgentLinkName}
		dummyLink = &netlink.Dummy{LinkAttrs: attrs}
	)

	testCases := []struct {
		name        string
		handleCalls func(handle *MockNetlinkHandle)
		error       error
	}{
		{
			name: "creates a link if its not there",
			handleCalls: func(handle *MockNetlinkHandle) {
				gomock.InOrder(
					handle.EXPECT().LinkByName(configuration.AgentLinkName).Return(nil, netlink.LinkNotFoundError{}),
					handle.EXPECT().LinkAdd(gomock.Any()).Return(nil),
					handle.EXPECT().LinkByName(configuration.AgentLinkName).Return(dummyLink, nil),
				)
			},
		},
		{
			name: "link creation fails",
			handleCalls: func(handle *MockNetlinkHandle) {
				gomock.InOrder(
					handle.EXPECT().LinkByName(configuration.AgentLinkName).Return(nil, netlink.LinkNotFoundError{}),
					handle.EXPECT().LinkAdd(gomock.Any()).Return(assert.AnError),
				)
			},
			error: assert.AnError,
		},
		{
			name: "does not create a link if there is one present",
			handleCalls: func(handle *MockNetlinkHandle) {
				gomock.InOrder(
					handle.EXPECT().LinkByName(configuration.AgentLinkName).Return(dummyLink, nil),
				)
			},
		},
		{
			name: "unknown error stops execution",
			handleCalls: func(handle *MockNetlinkHandle) {
				gomock.InOrder(
					handle.EXPECT().LinkByName(configuration.AgentLinkName).Return(nil, assert.AnError),
				)
			},
			error: assert.AnError,
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

			retriever := &agentLinkRetriever{
				netlinkHandle: handle,
			}
			ctx := context.Background()

			// trigger
			link, err := retriever.CreateOrGetLink(ctx)

			// validate
			if tc.error != nil {
				g.Expect(err).To(MatchError(tc.error))
			} else {
				g.Expect(link.Name()).To(Equal(configuration.AgentLinkName))
				g.Expect(link).ToNot(BeNil())
				g.Expect(err).ToNot(HaveOccurred())
			}
		})
	}
}

func TestAgentLink_SetupForAddrFamily(t *testing.T) {
	var (
		attrs     = netlink.LinkAttrs{Name: configuration.AgentLinkName}
		dummyLink = &netlink.Dummy{LinkAttrs: attrs}

		_, targetIp, _ = net.ParseCIDR("192.168.1.5/32")
		targetAddr     = &netlink.Addr{
			IPNet: targetIp,
		}
		_, otherIp, _ = net.ParseCIDR("192.168.1.3/32")
		otherAddr     = &netlink.Addr{
			IPNet: otherIp,
		}
		_, cidrOverlapWithTargetIp, _ = net.ParseCIDR("192.168.1.3/24")
		cidrOverlapTargetAddr         = &netlink.Addr{
			IPNet: cidrOverlapWithTargetIp,
		}
	)

	testCases := []struct {
		name        string
		handleCalls func(handle *MockNetlinkHandle)
		addrFamily  AddrFamily
		error       error
	}{
		{
			name: "associates addr if the interface doesnt have it but no other associated",
			handleCalls: func(handle *MockNetlinkHandle) {
				gomock.InOrder(
					// call to search for addr and return empty list
					handle.EXPECT().AddrList(dummyLink, 1).
						Return([]netlink.Addr{}, nil),
					// call to create addr association
					handle.EXPECT().AddrAdd(dummyLink, targetAddr).
						Return(nil),
				)
			},
			addrFamily: AddrFamily{
				LinkLocalAddr: targetAddr,
				Family:        1,
			},
		},
		{
			name: "associates addr if the interface doesnt have it but other addr associated",
			handleCalls: func(handle *MockNetlinkHandle) {
				gomock.InOrder(
					// call to search for addr but return an existing one not matching target
					handle.EXPECT().AddrList(dummyLink, 1).
						Return([]netlink.Addr{*otherAddr}, nil),
					// call to create addr association
					handle.EXPECT().AddrAdd(dummyLink, targetAddr).
						Return(nil),
				)
			},
			addrFamily: AddrFamily{
				LinkLocalAddr: targetAddr,
				Family:        1,
			},
		},
		{
			name: "does not associated if there is already an overlapping cidr to interface",
			handleCalls: func(handle *MockNetlinkHandle) {
				gomock.InOrder(
					// call to search for addr & return one with matching cidr
					handle.EXPECT().AddrList(dummyLink, 1).
						Return([]netlink.Addr{*cidrOverlapTargetAddr}, nil),
				)
			},
			addrFamily: AddrFamily{
				LinkLocalAddr: targetAddr,
				Family:        1,
			},
		},
		{
			name: "does not associated if there is one association present",
			handleCalls: func(handle *MockNetlinkHandle) {
				gomock.InOrder(
					// call to search for addr
					handle.EXPECT().AddrList(dummyLink, 1).
						Return([]netlink.Addr{*targetAddr}, nil),
				)
			},
			addrFamily: AddrFamily{
				LinkLocalAddr: targetAddr,
				Family:        1,
			},
		},
		{
			name: "stops execution if listing addresses fails",
			handleCalls: func(handle *MockNetlinkHandle) {
				gomock.InOrder(
					// call to search for addr but returned error
					handle.EXPECT().AddrList(dummyLink, 1).
						Return(nil, assert.AnError),
				)
			},
			addrFamily: AddrFamily{
				LinkLocalAddr: targetAddr,
				Family:        1,
			},
			error: assert.AnError,
		},
		{
			name: "stops execution if adding address fails",
			handleCalls: func(handle *MockNetlinkHandle) {
				gomock.InOrder(
					handle.EXPECT().AddrList(dummyLink, 1).
						Return([]netlink.Addr{*otherAddr}, nil),
					handle.EXPECT().AddrAdd(dummyLink, targetAddr).
						Return(assert.AnError),
				)
			},
			addrFamily: AddrFamily{
				LinkLocalAddr: targetAddr,
				Family:        1,
			},
			error: assert.AnError,
		},
		{
			name: "link-local addr must be specified",
			addrFamily: AddrFamily{
				Family: 1,
			},
			error: fmt.Errorf("family 0x01 does not specify a link-local addr to bind to"),
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
			err := al.SetupForAddrFamily(ctx, tc.addrFamily)

			// validate
			if tc.error != nil {
				g.Expect(err).To(MatchError(tc.error))
			} else {
				g.Expect(err).ToNot(HaveOccurred())
			}
		})
	}
}
