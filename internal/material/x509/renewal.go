package x509

// Working out when to replace a certificate.
//
// A certificate is valid for a fixed window, say 09:00 to 15:00. We want a new one
// before 15:00, with some margin. Two details are easy to get wrong.
//
// First, use the window on the certificate we were given, not the lifetime we asked
// for. We ask for 6 hours, STS may issue less, and it sets the start a few minutes in
// the past. Scheduling from "now plus 6 hours" would renew after it had expired.
//
// Second, renew partway through the window rather than a fixed time before the end.
// "Renew one hour before expiry" breaks on a one hour certificate: we would renew
// before it started.

import "time"

// minRenewalDelay is the shortest we will ever wait before trying a renewal.
const minRenewalDelay = 10 * time.Second

// renewalPoint picks the moment to replace a certificate valid from notBefore until
// notAfter. fraction is how far through that window to aim for, from
// --svid-renewal-fraction, so 0.5 replaces a 6 hour certificate after about 3 hours.
// jitter, from --svid-renewal-jitter, spreads the moment so a node's pods do not renew
// together: 0.1 lands it between 45% and 55%. draw supplies the random number.
func renewalPoint(notBefore, notAfter time.Time, fraction, jitter float64, draw func() float64) time.Time {
	lifetime := notAfter.Sub(notBefore)
	if lifetime <= 0 {
		return notAfter
	}
	at := fraction - jitter/2 + jitter*draw()
	return notBefore.Add(time.Duration(float64(lifetime) * at))
}

// renewalDelay works out how long to wait before the next renewal attempt. Normally the
// renewal moment is ahead and we wait until then.
//
// It can be in the past, if the certificate was short lived or earlier attempts failed.
// The floor matters there: the cache reads a non-positive refresh deadline as "never
// refresh", so returning one would leave the certificate to expire unrenewed.
func renewalDelay(now, at time.Time) time.Duration {
	if delay := at.Sub(now); delay > minRenewalDelay {
		return delay
	}
	return minRenewalDelay
}
