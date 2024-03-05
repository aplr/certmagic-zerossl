package zerossl

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/caddyserver/certmagic"
	"github.com/mholt/acmez/acme"
	"go.uber.org/zap"
)

// ZeroSSLIssuer makes an ACME issuer for getting certificates
// from ZeroSSL by automatically generating EAB credentials.
// Please be sure to set a valid email address in your config
// so you can access/manage your domains in your ZeroSSL account.
//
// This issuer is only needed for automatic generation of EAB
// credentials. If manually configuring/reusing EAB credentials,
// the standard ACMEIssuer may be used if desired.
type ACMEIssuer struct {
	*certmagic.ACMEIssuer

	APIKey string

	mu *sync.Mutex
}

var _ ZeroSSLIssuer = (*ACMEIssuer)(nil)

func newACMEIssuer(
	cfg *certmagic.Config,
	template ACMEIssuer,
) *ACMEIssuer {
	var acmeTemplate certmagic.ACMEIssuer
	if template.ACMEIssuer != nil {
		acmeTemplate = *template.ACMEIssuer
	}

	// set default CA endpoint to ZeroSSL production
	if acmeTemplate.CA == "" {
		acmeTemplate.CA = certmagic.ZeroSSLProductionCA
	}

	// create underlying ACMEIssuer
	template.ACMEIssuer = certmagic.NewACMEIssuer(cfg, acmeTemplate)

	// use the logger from the ACMEIssuer if none is set
	if template.Logger == nil {
		template.Logger = template.ACMEIssuer.Logger
	}

	template.mu = new(sync.Mutex)

	return &template
}

func (iss *ACMEIssuer) newAccountCallback(ctx context.Context, acmeIss *certmagic.ACMEIssuer, acct acme.Account) (acme.Account, error) {
	if acmeIss.ExternalAccount != nil {
		return acct, nil
	}
	var err error
	acmeIss.ExternalAccount, acct, err = iss.generateEABCredentials(ctx, acct)
	return acct, err
}

func (iss *ACMEIssuer) generateEABCredentials(ctx context.Context, acct acme.Account) (*acme.EAB, acme.Account, error) {
	var endpoint string
	var body io.Reader

	// there are two ways to generate EAB credentials: authenticated with
	// their API key, or unauthenticated with their email address
	if iss.APIKey != "" {
		qs := url.Values{"access_key": []string{iss.APIKey}}
		endpoint = fmt.Sprintf("%s/eab-credentials?%s", zerosslACMEAPI, qs.Encode())
	} else {
		email := iss.Email
		if email == "" {
			iss.Logger.Warn("missing email address for ZeroSSL; it is strongly recommended to set one for next time")
			email = "caddy@zerossl.com" // special email address that preserves backwards-compat, but which black-holes dashboard features, oh well
		}
		if len(acct.Contact) == 0 {
			// we borrow the email from config or the default email, so ensure it's saved with the account
			acct.Contact = []string{"mailto:" + email}
		}
		endpoint = zerosslACMEAPI + "/eab-credentials-email"
		form := url.Values{"email": []string{email}}
		body = strings.NewReader(form.Encode())
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, body)
	if err != nil {
		return nil, acct, fmt.Errorf("forming request: %v", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	req.Header.Set("User-Agent", certmagic.UserAgent)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, acct, fmt.Errorf("performing EAB credentials request: %v", err)
	}
	defer resp.Body.Close()

	var result struct {
		Success bool `json:"success"`
		Error   struct {
			Code int    `json:"code"`
			Type string `json:"type"`
		} `json:"error"`
		EABKID     string `json:"eab_kid"`
		EABHMACKey string `json:"eab_hmac_key"`
	}
	err = json.NewDecoder(resp.Body).Decode(&result)
	if err != nil {
		return nil, acct, fmt.Errorf("decoding API response: %v", err)
	}
	if result.Error.Code != 0 {
		return nil, acct, fmt.Errorf("failed getting EAB credentials: HTTP %d: %s (code %d)",
			resp.StatusCode, result.Error.Type, result.Error.Code)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, acct, fmt.Errorf("failed getting EAB credentials: HTTP %d", resp.StatusCode)
	}

	iss.Logger.Info("generated EAB credentials", zap.String("key_id", result.EABKID))

	return &acme.EAB{
		KeyID:  result.EABKID,
		MACKey: result.EABHMACKey,
	}, acct, nil
}

func (iss *ACMEIssuer) initialize() {
	iss.mu.Lock()
	defer iss.mu.Unlock()
	if iss.ACMEIssuer.NewAccountFunc == nil {
		iss.ACMEIssuer.NewAccountFunc = iss.newAccountCallback
	}
}

func (iss *ACMEIssuer) PreCheck(ctx context.Context, names []string, interactive bool) error {
	iss.initialize()
	return iss.ACMEIssuer.PreCheck(ctx, names, interactive)
}

func (iss *ACMEIssuer) Issue(ctx context.Context, csr *x509.CertificateRequest) (*certmagic.IssuedCertificate, error) {
	iss.initialize()
	return iss.ACMEIssuer.Issue(ctx, csr)
}

func (iss *ACMEIssuer) IssuerKey() string {
	iss.initialize()
	return iss.ACMEIssuer.IssuerKey()
}

func (iss *ACMEIssuer) Revoke(ctx context.Context, cert certmagic.CertificateResource, reason int) error {
	iss.initialize()
	return iss.ACMEIssuer.Revoke(ctx, cert, reason)
}

func (iss *ACMEIssuer) GetIssuer() ZeroSSLIssuer {
	return iss
}
