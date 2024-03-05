package zerossl

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"sync"
	"time"

	"github.com/caddyserver/certmagic"
	"go.uber.org/zap"
)

var (
	ErrAPIKeyMissing       = fmt.Errorf("ZeroSSL API key is missing")
	ErrInvalidRevokeReason = fmt.Errorf("invalid revoke reason")
)

const (
	// HTTPChallengePort is the officially-designated port for
	// the HTTP challenge according to ZeroSSL.
	HTTPChallengePort = 80
)

// Port variables must remain their defaults unless you
// forward packets from the defaults to whatever these
// are set to; otherwise ZeroSSL challenges will fail.
var (
	// HTTPPort is the port on which to serve HTTP
	// and, as such, the HTTP challenge (unless
	// Default.AltHTTPPort is set).
	HTTPPort = 80
)

type APIIssuer struct {
	// The key for ZeroSSL API
	APIKey string

	// Disable all HTTP challenges
	DisableHTTPChallenge bool

	// The host (ONLY the host, not port) to listen
	// on if necessary to start a listener to solve
	// a ZeroSSL challenge
	ListenHost string

	// The alternate port to use for the ZeroSSL HTTP
	// challenge. If non-zero, this port will be
	// used instead of HTTPChallengePort to spin up
	// a listener for the HTTP challenge
	AltHTTPPort int

	// The solver for the dns challenge;
	// usually this is a DNSSolver value
	// from this package
	DNSSolver Solver

	// TrustedRoots specifies a pool of root CA
	// certificates to trust when communicating
	// over a network to a peer.
	TrustedRoots *x509.CertPool

	// The maximum amount of time to allow for
	// obtaining a certificate. If empty, a
	// sensible default is used. If set, it
	// must not be too low so as to cancel
	// challenges too early.
	CertObtainTimeout time.Duration

	// Address of custom DNS resolver to be used
	// when communicating with ZeroSSL server
	Resolver string

	// Set a logger to configure logging; a default
	// logger must always be set; if no logging is
	// desired, set this to zap.NewNop().
	Logger *zap.Logger

	// Set a http proxy to use when issuing a certificate.
	// Default is http.ProxyFromEnvironment
	HTTPProxy func(*http.Request) (*url.URL, error)

	config     *certmagic.Config
	httpClient *http.Client

	// protects the above grouped fields
	mu *sync.Mutex
}

var _ ZeroSSLIssuer = (*APIIssuer)(nil)

func newAPIIssuer(
	cfg *certmagic.Config,
	template APIIssuer,
) (*APIIssuer, error) {
	if template.APIKey == "" {
		return nil, ErrAPIKeyMissing
	}

	if !template.DisableHTTPChallenge {
		template.DisableHTTPChallenge = DefaultAPI.DisableHTTPChallenge
	}
	if template.DNSSolver == nil {
		template.DNSSolver = DefaultAPI.DNSSolver
	}
	if template.CertObtainTimeout == 0 {
		template.CertObtainTimeout = DefaultAPI.CertObtainTimeout
	}
	if template.Resolver == "" {
		template.Resolver = DefaultAPI.Resolver
	}
	if template.Logger == nil {
		template.Logger = DefaultAPI.Logger
	}

	// absolutely do not allow a nil logger; that would panic
	if template.Logger == nil {
		template.Logger = certmagic.Default.Logger
	}

	if template.HTTPProxy == nil {
		template.HTTPProxy = DefaultAPI.HTTPProxy
	}
	if template.HTTPProxy == nil {
		template.HTTPProxy = http.ProxyFromEnvironment
	}

	template.config = cfg
	template.mu = new(sync.Mutex)

	dialer := &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 2 * time.Minute,
	}
	if template.Resolver != "" {
		dialer.Resolver = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{
					Timeout: 15 * time.Second,
				}).DialContext(ctx, network, template.Resolver)
			},
		}
	}
	transport := &http.Transport{
		Proxy:                 template.HTTPProxy,
		DialContext:           dialer.DialContext,
		TLSHandshakeTimeout:   30 * time.Second, // increase to 30s requested in #175
		ResponseHeaderTimeout: 30 * time.Second, // increase to 30s requested in #175
		ExpectContinueTimeout: 2 * time.Second,
		ForceAttemptHTTP2:     true,
	}
	if template.TrustedRoots != nil {
		transport.TLSClientConfig = &tls.Config{
			RootCAs: template.TrustedRoots,
		}
	}
	template.httpClient = &http.Client{
		Transport: transport,
		Timeout:   HTTPTimeout,
	}

	return &template, nil
}

func (iss *APIIssuer) IssuerKey() string {
	// TODO: probably dynamic?
	return "api-zerossl-com-certificates"
}

func (iss *APIIssuer) PreCheck(ctx context.Context, names []string, interactive bool) error {
	for _, name := range names {
		if !certmagic.SubjectQualifiesForPublicCert(name) {
			return fmt.Errorf("subject does not qualify for a public certificate: %s", name)
		}
	}

	return nil
}

func (iss *APIIssuer) Issue(ctx context.Context, csr *x509.CertificateRequest) (*certmagic.IssuedCertificate, error) {
	if iss.config == nil {
		panic("missing config pointer (must be APIIssuer)")
	}

	var isRetry bool
	if attempts, ok := ctx.Value(AttemptsCtxKey).(*int); ok {
		isRetry = *attempts > 0
	}

	cert, err := iss.doIssue(ctx, csr, isRetry)
	if err != nil {
		return nil, err
	}

	return cert, nil
}

func (iss *APIIssuer) doIssue(
	ctx context.Context,
	csr *x509.CertificateRequest,
	isRetry bool,
) (*certmagic.IssuedCertificate, error) {
	client, err := iss.newClient()
	if err != nil {
		return nil, err
	}

	nameSet := namesFromCSR(csr)

	if err := iss.throttle(ctx, nameSet); err != nil {
		return nil, err
	}

	cert, err := client.ObtainCertificateUsingCSR(ctx, csr)
	if err != nil {
		return nil, fmt.Errorf("%v %w", nameSet, err)
	}

	ic := &certmagic.IssuedCertificate{
		Certificate: cert.ChainPEM,
		Metadata:    cert,
	}

	return ic, nil
}

func (iss *APIIssuer) throttle(
	ctx context.Context,
	names []string,
) error {
	rateLimiterMu.Lock()
	if rateLimiter == nil {
		rateLimiter = certmagic.NewRateLimiter(RateLimitEvents, RateLimitEventsWindow)
	}
	rateLimiterMu.Unlock()
	iss.Logger.With(
		zap.Strings("identifiers", names),
	).Info("waiting on internal rate limiter")
	err := rateLimiter.Wait(ctx)
	if err != nil {
		return err
	}
	iss.Logger.With(
		zap.Strings("identifiers", names),
	).Info("done waiting on internal rate limiter")
	return nil
}

func (iss *APIIssuer) Revoke(
	ctx context.Context,
	cert certmagic.CertificateResource,
	reason int,
) error {
	data, ok := getIssuerData(cert)
	if !ok {
		return fmt.Errorf("no issuer data found")
	}

	client, err := iss.newClient()
	if err != nil {
		return err
	}

	return client.revokeCertificate(ctx, data.ID, reason)
}

func getIssuerData(cert certmagic.CertificateResource) (*Certificate, bool) {
	if cert.IssuerData == nil {
		return nil, false
	}

	issuerData, ok := cert.IssuerData.(*Certificate)
	if !ok {
		return nil, false
	}

	return issuerData, true
}

func (iss *APIIssuer) GetIssuer() ZeroSSLIssuer {
	return iss
}

// MARK: - Client

func (iss *APIIssuer) newClient() (*Client, error) {
	certObtainTimeout := iss.CertObtainTimeout
	if certObtainTimeout == 0 {
		certObtainTimeout = DefaultAPI.CertObtainTimeout
	}

	logger := iss.Logger.Named("zerossl")

	client := &Client{
		APIKey:      iss.APIKey,
		PollTimeout: certObtainTimeout,
		UserAgent:   buildUAString(),
		HttpClient:  iss.httpClient,
		Logger:      logger,
	}

	if iss.DNSSolver != nil {
		// if dns solver is set, use it exclusively
		client.ChallengeSolvers[string(ChallengeTypeDNS)] = iss.DNSSolver
	} else if !iss.DisableHTTPChallenge {
		// use http solver if it is not disabled
		useHTTPPort := HTTPChallengePort
		if HTTPPort > 0 && HTTPPort != HTTPChallengePort {
			useHTTPPort = HTTPPort
		}
		if iss.AltHTTPPort > 0 {
			useHTTPPort = iss.AltHTTPPort
		}
		client.ChallengeSolvers[string(ChallengeTypeHTTP)] = distributedSolver{
			storage:                iss.config.Storage,
			storageKeyIssuerPrefix: storageKeyCAPrefix(iss.IssuerKey()),
			solver: &httpSolver{
				issuer:  iss,
				address: net.JoinHostPort(iss.ListenHost, strconv.Itoa(useHTTPPort)),
			},
		}

	}

	return client, nil
}

// MARK: - Helpers

func namesFromCSR(csr *x509.CertificateRequest) []string {
	nameSet := []string{}
	nameSet = append(nameSet, csr.Subject.CommonName)
	nameSet = append(nameSet, csr.DNSNames...)
	nameSet = append(nameSet, csr.EmailAddresses...)

	for _, v := range csr.IPAddresses {
		nameSet = append(nameSet, v.String())
	}

	for _, v := range csr.URIs {
		nameSet = append(nameSet, v.String())
	}

	return nameSet
}

func storageKeyCAPrefix(issuerKey string) string {
	return path.Join(prefixZeroSSL, certmagic.StorageKeys.Safe(issuerKey))
}

// DefaultAPI specifies default settings to use for APIIssuers.
// Using this value is optional but can be convenient.
var DefaultAPI = APIIssuer{
	Logger: certmagic.Default.Logger,
}

var (
	rateLimiter   *certmagic.RingBufferRateLimiter
	rateLimiterMu sync.RWMutex

	// RateLimitEvents is how many new events can be allowed
	// in RateLimitEventsWindow.
	RateLimitEvents = 10

	// RateLimitEventsWindow is the size of the sliding
	// window that throttles events.
	RateLimitEventsWindow = 10 * time.Second
)
