package cmd

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"go.amzn.com/eks/eks-pod-identity-agent/configuration"
)

func TestValidateBindHosts(t *testing.T) {
	testCases := []struct {
		name    string
		hosts   []string
		wantErr bool
	}{
		{
			name:  "default link-local hosts are allowed",
			hosts: []string{configuration.DefaultIpv4TargetHost, "[" + configuration.DefaultIpv6TargetHost + "]"},
		},
		{
			name:  "bare ipv6 link-local host is allowed",
			hosts: []string{configuration.DefaultIpv6TargetHost},
		},
		{
			name:  "loopback is allowed",
			hosts: []string{"127.0.0.1"},
		},
		{
			name:  "ipv6 loopback is allowed",
			hosts: []string{"::1"},
		},
		{
			name:  "localhost is allowed",
			hosts: []string{"localhost"},
		},
		{
			name:    "wildcard bind is rejected",
			hosts:   []string{"0.0.0.0"},
			wantErr: true,
		},
		{
			name:    "ipv6 wildcard bind is rejected",
			hosts:   []string{"::"},
			wantErr: true,
		},
		{
			name:    "arbitrary routable address is rejected",
			hosts:   []string{"10.0.0.5"},
			wantErr: true,
		},
		{
			name:    "a disallowed host alongside allowed ones is rejected",
			hosts:   []string{configuration.DefaultIpv4TargetHost, "0.0.0.0"},
			wantErr: true,
		},
		{
			name:    "unparseable host is rejected",
			hosts:   []string{"not-an-ip"},
			wantErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateBindHosts(tc.hosts)
			if tc.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
