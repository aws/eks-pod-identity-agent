package x509

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestRenewalPointIsAFractionOfTheIssuedWindow(t *testing.T) {
	notBefore := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	notAfter := notBefore.Add(6 * time.Hour)

	tests := []struct {
		name     string
		fraction float64
		jitter   float64
		draw     float64
		want     time.Duration // from notBefore
	}{
		{
			name: "half life with jitter disabled", fraction: 0.5, jitter: 0, draw: 0.5,
			want: 3 * time.Hour,
		},
		{
			// The band is [fraction - jitter/2, fraction + jitter/2), so the bottom
			// of a 0.1 jitter at 0.5 is 0.45 of six hours.
			name: "bottom of the jitter band", fraction: 0.5, jitter: 0.1, draw: 0,
			want: 2*time.Hour + 42*time.Minute,
		},
		{
			name: "middle of the jitter band", fraction: 0.5, jitter: 0.1, draw: 0.5,
			want: 3 * time.Hour,
		},
		{
			// 0.55 of six hours. The draw is exclusive of one, so this is the limit
			// rather than a reachable value.
			name: "top of the jitter band", fraction: 0.5, jitter: 0.1, draw: 1,
			want: 3*time.Hour + 18*time.Minute,
		},
		{
			name: "a fraction other than half is honoured", fraction: 0.8, jitter: 0, draw: 0.5,
			want: 4*time.Hour + 48*time.Minute,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			at := renewalPoint(notBefore, notAfter, tc.fraction, tc.jitter, func() float64 { return tc.draw })
			assert.Equal(t, notBefore.Add(tc.want), at)
		})
	}
}

// TestRenewalPointDerivesFromTheIssuedWindow pins the behaviour that matters most
// in practice: STS backdates NotBefore and may shorten the lifetime, so a schedule
// computed from the requested duration renews late.
func TestRenewalPointDerivesFromTheIssuedWindow(t *testing.T) {
	requested := 6 * time.Hour
	// What STS actually issued: backdated five minutes and cut to four hours.
	notBefore := time.Date(2026, 9, 29, 11, 55, 0, 0, time.UTC)
	notAfter := notBefore.Add(4 * time.Hour)

	at := renewalPoint(notBefore, notAfter, 0.5, 0, func() float64 { return 0.5 })

	assert.Equal(t, notBefore.Add(2*time.Hour), at, "the point is half of the issued window")
	assert.True(t, at.Before(notBefore.Add(requested/2)),
		"scheduling from the requested duration would renew later than half the issued life")
}

// TestRenewalPointSpreadsIdenticalLifetimes is the anti-thundering-herd assertion:
// two workloads issued the same window must not land on one instant.
func TestRenewalPointSpreadsIdenticalLifetimes(t *testing.T) {
	notBefore := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	notAfter := notBefore.Add(6 * time.Hour)

	first := renewalPoint(notBefore, notAfter, 0.5, 0.1, func() float64 { return 0.1 })
	second := renewalPoint(notBefore, notAfter, 0.5, 0.1, func() float64 { return 0.9 })

	assert.NotEqual(t, first, second)

	// Both stay strictly inside the window, which is what startup validation of the
	// fraction and jitter band guarantees and what this confirms holds in the
	// arithmetic.
	for _, at := range []time.Time{first, second} {
		assert.True(t, at.After(notBefore))
		assert.True(t, at.Before(notAfter))
	}
}

func TestRenewalPointHandlesADegenerateWindow(t *testing.T) {
	at := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	assert.Equal(t, at, renewalPoint(at, at, 0.5, 0.1, func() float64 { return 0.5 }),
		"a window with no duration renews at its end rather than before its start")
}

func TestRenewalDelayFloorsAPassedPoint(t *testing.T) {
	now := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)

	assert.Equal(t, 2*time.Hour, renewalDelay(now, now.Add(2*time.Hour)))
	assert.Equal(t, minRenewalDelay, renewalDelay(now, now.Add(-time.Hour)),
		"a point already passed waits the floor rather than zero, so a late renewal is prompt without looping")
	assert.Equal(t, minRenewalDelay, renewalDelay(now, now.Add(time.Second)))
}
