package csidriver

import (
	"context"
	"net"
	"time"

	"github.com/sirupsen/logrus"
)

const (
	// waitDialTimeout bounds one connect to the agent's socket.
	waitDialTimeout = time.Second
	// waitInterval is the pause between connects.
	waitInterval = time.Second
	// waitLogEvery is how many failed connects pass between log lines.
	waitLogEvery = 30
)

// WaitForSocket blocks until the Unix socket at path accepts a connection, or ctx ends.
// The driver registers only after the agent's socket answers, so a pod scheduled before
// the agent serves, or with workload identity off, waits in ContainerCreating rather than
// starting with an empty socket directory. A connect rather than a stat, so a socket left
// by a killed agent does not count.
func WaitForSocket(ctx context.Context, log *logrus.Entry, path string) error {
	for attempt := 0; ; attempt++ {
		conn, err := net.DialTimeout("unix", path, waitDialTimeout)
		if err == nil {
			_ = conn.Close()
			return nil
		}
		if attempt%waitLogEvery == 0 {
			log.Infof("Waiting for the agent to serve %s before registering the CSI driver: %v", path, err)
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(waitInterval):
		}
	}
}
