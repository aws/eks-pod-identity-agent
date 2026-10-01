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

// renewalPoint picks the moment to replace a certificate that is valid from
// notBefore until notAfter.
//
// fraction is how far through the window to aim for, and comes from
// --svid-renewal-fraction. At the default of 0.5 we aim for halfway, so a 6 hour
// certificate is replaced after about 3 hours.
//
// jitter spreads that moment out a little so pods do not all renew together, and
// comes from --svid-renewal-jitter. At the default of 0.1 the moment lands anywhere
// between 45% and 55% of the way through, picked at random per certificate.
//
// draw supplies that random number between 0 and 1. Tests pass a fixed value so the
// result is predictable.
func renewalPoint(notBefore, notAfter time.Time, fraction, jitter float64, draw func() float64) time.Time {
	lifetime := notAfter.Sub(notBefore)
	if lifetime <= 0 {
		return notAfter
	}
	at := fraction - jitter/2 + jitter*draw()
	return notBefore.Add(time.Duration(float64(lifetime) * at))
}

// renewalDelay works out how long to wait before the next renewal attempt.
//
// Normally the renewal moment is ahead of us and we wait until then. It can be in the
// past, if the certificate was short lived or earlier attempts failed, and then we wait
// ten seconds rather than retrying immediately. Every attempt costs the customer a
// signing operation, so retrying without a pause would spend them in a loop.
func renewalDelay(now, at time.Time) time.Duration {
	if delay := at.Sub(now); delay > minRenewalDelay {
		return delay
	}
	return minRenewalDelay
}
