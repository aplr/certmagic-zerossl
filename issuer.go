package zerossl

import (
	"context"
	"crypto/x509"
	"fmt"
	"net/http"

	"github.com/caddyserver/certmagic"
)

type ZeroSSLIssuer interface {
	certmagic.PreChecker
	certmagic.Revoker
	certmagic.Issuer

	HTTPChallengeHandler(http.Handler) http.Handler
	GetIssuer() ZeroSSLIssuer
}

type Issuer struct {
	issuer ZeroSSLIssuer
}

var _ ZeroSSLIssuer = (*Issuer)(nil)

func NewIssuer(cfg *certmagic.Config, template ZeroSSLIssuer) (*Issuer, error) {
	issuer := new(Issuer)

	if acmeIssuer, ok := template.(*ACMEIssuer); ok {
		issuer.issuer = newACMEIssuer(cfg, *acmeIssuer)
	} else if apiIssuer, ok := template.(*APIIssuer); ok {
		apiIssuer, err := newAPIIssuer(cfg, *apiIssuer)
		if err != nil {
			return nil, err
		}
		issuer.issuer = apiIssuer
	} else {
		return nil, fmt.Errorf("invalid issuer type")
	}

	return issuer, nil
}

func (iss *Issuer) PreCheck(ctx context.Context, names []string, interactive bool) error {
	return iss.issuer.PreCheck(ctx, names, interactive)
}

func (iss *Issuer) Issue(ctx context.Context, csr *x509.CertificateRequest) (*certmagic.IssuedCertificate, error) {
	return iss.issuer.Issue(ctx, csr)
}

func (iss *Issuer) IssuerKey() string {
	return iss.issuer.IssuerKey()
}

func (iss *Issuer) Revoke(ctx context.Context, cert certmagic.CertificateResource, reason int) error {
	return iss.issuer.Revoke(ctx, cert, reason)
}

func (iss *Issuer) GetIssuer() ZeroSSLIssuer {
	return iss.issuer
}

func (iss *Issuer) HTTPChallengeHandler(h http.Handler) http.Handler {
	return iss.issuer.HTTPChallengeHandler(h)
}

const (
	prefixZeroSSL  = "zerossl"
	zerosslACMEAPI = "https://api.zerossl.com/acme"
	zerosslCertAPI = "https://api.zerossl.com/certificates"
)
