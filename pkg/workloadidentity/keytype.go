package workloadidentity

import (
	"fmt"
	"strings"
)

// KeyType is the kind of key pair the agent generates for each X.509-SVID.
//
// An operator fixes one for the whole agent at startup. A workload cannot ask for a
// particular kind, because the SPIFFE Workload API has no field to ask with. SPIRE
// settles it the same way, as a static choice made when the agent boots, and these
// names match SPIRE's so an operator moving between the two reads one spelling.
type KeyType string

const (
	// KeyTypeECP256 is ECDSA on NIST P-256.
	KeyTypeECP256 KeyType = "ec-p256"
	// KeyTypeECP384 is ECDSA on NIST P-384.
	KeyTypeECP384 KeyType = "ec-p384"
	// KeyTypeRSA2048 is RSA with a 2048 bit modulus.
	KeyTypeRSA2048 KeyType = "rsa-2048"
	// KeyTypeRSA4096 is RSA with a 4096 bit modulus.
	KeyTypeRSA4096 KeyType = "rsa-4096"
)

// DefaultKeyType is what the agent generates when an operator names nothing.
//
// P-256 is the SPIFFE default and what the onboarding guide's own sample generates. It
// is also far the cheapest of the four to generate, which matters because the agent
// makes a fresh key for every pod at every renewal. Generating RSA-4096 takes long
// enough to be visible on that path.
//
// Which of the four STS accepts is not confirmed. On 2026-10-02 they called the list
// reasonable and deferred the detail, so choosing anything other than this is choosing
// something untested against the real service.
const DefaultKeyType = KeyTypeECP256

// KeyTypes returns every accepted value, in the order a flag's usage string lists them.
func KeyTypes() []KeyType {
	return []KeyType{KeyTypeECP256, KeyTypeECP384, KeyTypeRSA2048, KeyTypeRSA4096}
}

// Validate reports whether k is one of the four the agent can generate.
func (k KeyType) Validate() error {
	for _, known := range KeyTypes() {
		if k == known {
			return nil
		}
	}
	return fmt.Errorf("%q is not a key type the agent can generate, which are %s", string(k), KeyTypeList())
}

// KeyTypeList renders the accepted values for a flag's usage string and for errors, so
// the two cannot name different sets.
func KeyTypeList() string {
	names := make([]string, 0, len(KeyTypes()))
	for _, k := range KeyTypes() {
		names = append(names, string(k))
	}
	return strings.Join(names, ", ")
}
