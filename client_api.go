package zerossl

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/caddyserver/certmagic"
)

type IdentifierValidation struct {
	HTTPValidationURL     url.URL  `json:"file_validation_url_http"`
	HTTPValidationContent []string `json:"file_validation_content"`
	DNSCNAMERecordName    string   `json:"cname_validation_p1"`
	DNSCNAMERecordPointer string   `json:"cname_validation_p2"`
}

type OrderValidation struct {
	IdentifierValidations map[string]IdentifierValidation `json:"other_methods"`
}

type Order struct {
	// ID is the unique identifier for the order.
	ID string `json:"id"`

	// CommonName is the common name for the certificate.
	CommonName string `json:"common_name"`

	// AdditionalDomains is a comma-separated list of additional domains
	AdditionalDomains string `json:"additional_domains"`

	// Status is the status of the order.
	Status string `json:"status"`

	// Validation is the validation information for the order.
	Validation OrderValidation `json:"validation"`
}

func (c *Client) createCertificate(
	ctx context.Context,
	identifiers []string,
	csr *x509.CertificateRequest,
) (*Order, error) {
	endpoint := c.createEndpoint("")

	// create form data
	formData := url.Values{
		"certificate_domains": []string{strings.Join(identifiers, ",")},
		"certificate_csr":     []string{string(csr.Raw)},
	}
	body := strings.NewReader(formData.Encode())

	// create request
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, body)
	if err != nil {
		return nil, fmt.Errorf("ZeroSSL create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// send request
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("performing create certificate request: %v", err)
	}
	defer resp.Body.Close()

	var result Order
	err = json.NewDecoder(resp.Body).Decode(&result)
	if err != nil {
		return nil, fmt.Errorf("decoding zerossl create API response: %v", err)
	}

	return &result, nil
}

func (c *Client) downloadCertificate(
	ctx context.Context,
	certId string,
) (*certmagic.IssuedCertificate, error) {
	endpoint := c.createEndpoint(fmt.Sprintf("/%s/download/return", certId))

	// create request
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("ZeroSSL dowload request: %v", err)
	}

	// send request
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("performing dowload certificate request: %v", err)
	}
	defer resp.Body.Close()

	var result struct {
		CertificateCrt    string `json:"certificate.crt"`
		CertificateBundle string `json:"ca_bundle.crt"`
	}
	err = json.NewDecoder(resp.Body).Decode(&result)
	if err != nil {
		return nil, fmt.Errorf("decoding zerossl download API response: %v", err)
	}

	return &certmagic.IssuedCertificate{
		Certificate: []byte(result.CertificateCrt),
		Metadata:    map[string]string{"id": certId},
	}, nil
}

func (c *Client) revokeCertificate(ctx context.Context, certId string, reason int) error {
	reasonStr, err := getRevokeReason(reason)
	if err != nil {
		return err
	}

	endpoint := c.createEndpoint(fmt.Sprintf("/%s/revoke", certId))

	// create form data
	formData := url.Values{"reason": []string{reasonStr}}
	body := strings.NewReader(formData.Encode())

	// create request
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, body)
	if err != nil {
		return fmt.Errorf("ZeroSSL revoke request: %v", err)
	}

	// send request
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("performing revoke certificate request: %v", err)
	}
	defer resp.Body.Close()

	var result struct {
		Success int8 `json:"success"`
	}
	err = json.NewDecoder(resp.Body).Decode(&result)
	if err != nil {
		return fmt.Errorf("decoding zerossl revoke response: %v", err)
	}

	if result.Success != 1 {
		return fmt.Errorf("revoking certificate failed")
	}

	return nil
}

func (c *Client) createEndpoint(path string) string {
	qs := url.Values{"access_key": []string{c.APIKey}}
	return fmt.Sprintf("%s%s?%s", zerosslCertAPI, path, qs.Encode())
}

func getRevokeReason(reason int) (string, error) {
	switch reason {
	case 0:
		return "Unspecified", nil
	case 1:
		return "keyCompromise", nil
	case 3:
		return "affiliationChanged", nil
	case 4:
		return "Superseded", nil
	case 5:
		return "cessationOfOperation", nil
	default:
		return "", ErrInvalidRevokeReason
	}
}
