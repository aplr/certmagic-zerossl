package zerossl

import (
	"crypto/x509"
)

// createIdentifiersUsingCSR extracts the list of identifiers from the
// given Certificate Signing Request.
func createIdentifiersUsingCSR(csr *x509.CertificateRequest) ([]Identifier, error) {
	var ids []Identifier

	for _, name := range csr.DNSNames {
		ids = append(ids, Identifier{
			Type:  "dns",
			Value: name,
		})
	}

	for _, ip := range csr.IPAddresses {
		ids = append(ids, Identifier{
			Type:  "ip",
			Value: ip.String(),
		})
	}

	return ids, nil
}
