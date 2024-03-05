package zerossl

// Certificate represents a certificate chain, which we usually refer
// to as "a certificate" because in practice an end-entity certificate
// is seldom useful/practical without a chain. This structure can be
// JSON-encoded and stored alongside the certificate chain to preserve
// potentially-useful metadata.
type Certificate struct {
	ID string `json:"id"`
	// The PEM-encoded certificate chain, end-entity first.
	// It is excluded from JSON marshalling since the
	// chain is usually stored in its own file.
	ChainPEM []byte `json:"-"`
}
