package zerossl

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	weakrand "math/rand"
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/mholt/acmez/acme"
	"go.uber.org/zap"
)

type Client struct {
	APIKey           string
	PollTimeout      time.Duration
	UserAgent        string
	HttpClient       *http.Client
	Logger           *zap.Logger
	ChallengeSolvers map[string]Solver
}

// CSRSource is an interface that provides users of this
// package the ability to provide a CSR as part of the
// ZeroSSL flow. This allows the final CSR to be provided
// just before the Order is finalized.
type CSRSource interface {
	CSR(context.Context) (*x509.CertificateRequest, error)
}

// ObtainCertificateUsingCSRSource obtains all resulting certificate chains using the given
// Identifiers and the CSRSource. The CSRSource can be used to create and sign a final
// CSR to be submitted to the ZeroSSL server just before finalization. The CSR  must be completely
// and properly filled out, because the provided Identifiers will be validated against
// the Identifiers that can be extracted from the CSR. This package currently supports the
// DNS, IP address, Permanent Identifier and Hardware Module Name identifiers. The Subject
// CommonName is NOT considered.
//
// The CSR's Raw field containing the DER encoded signed certificate request must also be
// set. This usually involves creating a template CSR, then calling x509.CreateCertificateRequest,
// then x509.ParseCertificateRequest on the output.
//
// The method implements every single part of the ZeroSSL flow.
func (c *Client) ObtainCertificateUsingCSRSource(
	ctx context.Context,
	identifiers []Identifier,
	source CSRSource,
) (*Certificate, error) {
	if source == nil {
		return nil, errors.New("missing CSR source")
	}

	// remember which challenge types failed for which identifiers
	// so we can retry with other challenge types
	failedChallengeTypes := make(failedChallengeMap)

	// get the CSR from its source
	csr, err := source.CSR(ctx)
	if err != nil {
		return nil, fmt.Errorf("getting CSR from source: %w", err)
	}
	if csr == nil {
		return nil, errors.New("source did not provide CSR")
	}

	var identifierStrings []string
	for _, id := range identifiers {
		identifierStrings = append(identifierStrings, id.Value)
	}

	const maxAttempts = 3 // hard cap on number of retries for good measure
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		if attempt > 1 {
			select {
			case <-time.After(1 * time.Second):
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}

		// create order for a new certificate
		order, err := c.createCertificate(ctx, identifierStrings, csr)
		if err != nil {
			return nil, fmt.Errorf("creating new order: %w", err)
		}

		// solve one challenge for each authz on the order
		err = c.solveChallenges(ctx, order, failedChallengeTypes)

		// yay, we win!
		if err == nil {
			break
		}

		// for some errors, we can retry with different challenge types
		var problem acme.Problem
		if errors.As(err, &problem) {
			authz, haveAuthz := problem.Resource.(acme.Authorization)
			if c.Logger != nil {
				l := c.Logger
				if haveAuthz {
					l = l.With(zap.String("identifier", authz.IdentifierValue()))
				}
				l.With(
					zap.Object("problem", problem),
					zap.String("order", order.Location),
					zap.Int("attempt", attempt),
					zap.Int("max_attempts", maxAttempts),
				).Error("validating authorization")
			}
			errStr := "solving challenge"
			if haveAuthz {
				errStr += ": " + authz.IdentifierValue()
			}
			err = fmt.Errorf("%s: %w", errStr, err)
			if errors.As(err, &retryableErr{}) {
				continue
			}
			return nil, err
		}

		return nil, fmt.Errorf("solving challenges: %w (order=%s)", err, order.Location)
	}

	if c.Logger != nil {
		c.Logger.Info("validations succeeded; finalizing order", zap.String("order", order.Location))
	}

	// validate the order identifiers
	if err := validateOrderIdentifiers(order, csr); err != nil {
		return nil, fmt.Errorf("validating order identifiers: %w", err)
	}

	// finalize the order, which requests the CA to issue us a certificate
	order, err = c.Client.FinalizeOrder(ctx, account, order, csr.Raw)
	if err != nil {
		return nil, fmt.Errorf("finalizing order %s: %w", order.Location, err)
	}

	// finally, download the certificate
	certChains, err := c.Client.GetCertificateChain(ctx, account, order.Certificate)
	if err != nil {
		return nil, fmt.Errorf("downloading certificate chain from %s: %w (order=%s)",
			order.Certificate, err, order.Location)
	}

	if c.Logger != nil {
		if len(certChains) == 0 {
			c.Logger.Info("no certificate chains offered by server")
		} else {
			c.Logger.Info("successfully downloaded available certificate chains",
				zap.Int("count", len(certChains)),
				zap.String("first_url", certChains[0].URL))
		}
	}

	return certChains, nil
}

// csrSource implements the CSRSource interface and is used internally
// to pass a CSR to ObtainCertificateUsingCSRSource from the existing
// ObtainCertificateUsingCSR method.
type csrSource struct {
	csr *x509.CertificateRequest
}

func (i *csrSource) CSR(_ context.Context) (*x509.CertificateRequest, error) {
	return i.csr, nil
}

var _ CSRSource = (*csrSource)(nil)

func (c *Client) ObtainCertificateUsingCSR(
	ctx context.Context,
	csr *x509.CertificateRequest,
) (*Certificate, error) {
	if csr == nil {
		return nil, errors.New("missing CSR")
	}

	ids, err := createIdentifiersUsingCSR(csr)
	if err != nil {
		return nil, err
	}
	if len(ids) == 0 {
		return nil, errors.New("no identifiers found")
	}

	csrSource := &csrSource{
		csr: csr,
	}

	return c.ObtainCertificateUsingCSRSource(ctx, ids, csrSource)
}

func createValidationState(identifier Identifier, validation IdentifierValidation) *validationState {
	var challenges []Challenge

	challenges = append(challenges, Challenge{
		Type:                ChallengeTypeHTTP,
		HTTPResourcePath:    validation.HTTPValidationURL.Path,
		HTTPResourcePayload: validation.HTTPValidationContent,
		Identifier:          identifier,
	})

	challenges = append(challenges, Challenge{
		Type:                  ChallengeTypeDNS,
		DNSCNAMERecordName:    validation.DNSCNAMERecordName,
		DNSCNAMERecordPointer: validation.DNSCNAMERecordPointer,
		Identifier:            identifier,
	})

	return &validationState{
		identifier: identifier,
		validation: validation,
		challenges: challenges,
	}
}

// getValidationObjects constructs stateful validation objects for each validation on the order.
// It includes all validations regardless of their status so that they can be
// deactivated at the end if necessary. Be sure to check valdation status before operating
// on the validation; not all will be "pending" - some authorizations might already be valid.
func (c *Client) getValidationObjects(ctx context.Context, order *Order, failedChallengeTypes failedChallengeMap) []*validationState {
	var validationStates []*validationState

	// start by allowing each validation solver to present for its challenge
	for identifier, validations := range order.Validation.IdentifierValidations {
		validationState := createValidationState(
			// TODO: this could also be `ip`?
			Identifier{Type: "dns", Value: identifier},
			validations,
		)

		// add all offered challenge types to our memory if they
		// arent't there already; we use this for statistics to
		// choose the most successful challenge type over time;
		// if initial fill, randomize challenge order
		preferredChallengesMu.Lock()
		preferredWasEmpty := len(preferredChallenges) == 0
		for _, chal := range validationState.challenges {
			preferredChallenges.addUnique(string(chal.Type))
		}
		if preferredWasEmpty {
			randomSourceMu.Lock()
			randomSource.Shuffle(len(preferredChallenges), func(i, j int) {
				preferredChallenges[i], preferredChallenges[j] =
					preferredChallenges[j], preferredChallenges[i]
			})
			randomSourceMu.Unlock()
		}
		preferredChallengesMu.Unlock()

		// copy over any challenges that are not known to have already
		// failed, making them candidates for solving for this authz
		failedChallengeTypes.enqueueUnfailedChallenges(validationState)

		validationStates = append(validationStates, validationState)
	}

	// sort validations so that challenges which require waiting go first; no point
	// in getting authorizations quickly while others will take a long time
	sort.SliceStable(validationStates, func(i, j int) bool {
		_, iIsWaiter := validationStates[i].currentSolver.(Waiter)
		_, jIsWaiter := validationStates[j].currentSolver.(Waiter)
		// "if i is a waiter, and j is not a waiter, then i is less than j"
		return iIsWaiter && !jIsWaiter
	})

	return validationStates
}

func (c *Client) solveChallenges(
	ctx context.Context,
	order *Order,
	failedChallengeTypes failedChallengeMap,
) error {
	validationStates := c.getValidationObjects(ctx, order, failedChallengeTypes)

	// when the function returns, make sure we clean up any and all resources
	defer func() {
		var err error

		// always clean up any remaining challenge solvers
		for _, vs := range validationStates {
			if vs.currentSolver == nil {
				// happens when validation state ended on a challenge we have no
				// solver for or if we have already cleaned up this solver
				continue
			}
			if err = vs.currentSolver.CleanUp(ctx, vs.currentChallenge); err != nil {
				c.Logger.With(
					zap.String("identifier", vs.identifier.Value),
					zap.String("challenge_type", string(vs.currentChallenge.Type)),
					zap.Error(err),
				).Error("cleaning up solver")
			}
		}

		if err == nil {
			return
		}

		// if this function returns with an error, make sure to deactivate
		// all pending or valid authorization objects so they don't "leak"
		// See: https://github.com/go-acme/lego/issues/383 and https://github.com/go-acme/lego/issues/353
		for _, vs := range validationStates {
			if vs.Status != acme.StatusPending && vs.Status != acme.StatusValid {
				continue
			}
			updatedAuthz, err := c.Client.DeactivateAuthorization(ctx, account, authz.Location)
			if err != nil {
				if c.Logger != nil {
					c.Logger.Error("deactivating authorization",
						zap.String("identifier", authz.IdentifierValue()),
						zap.String("authz", authz.Location),
						zap.Error(err))
				}
			}
			authz.Authorization = updatedAuthz
		}
	}()

	// present for all challenges first; this allows them all to begin any
	// slow tasks up front if necessary before we start polling/waiting
	for _, authz := range authzStates {
		// see §7.1.6 for state transitions
		if authz.Status != acme.StatusPending && authz.Status != acme.StatusValid {
			return fmt.Errorf("authz %s has unexpected status; order will fail: %s", authz.Location, authz.Status)
		}
		if authz.Status == acme.StatusValid {
			continue
		}

		err = c.presentForNextChallenge(ctx, authz)
		if err != nil {
			return err
		}
	}

	// now that all solvers have had the opportunity to present, tell
	// the server to begin the selected challenge for each authz
	for _, authz := range authzStates {
		err = c.initiateCurrentChallenge(ctx, authz)
		if err != nil {
			return err
		}
	}

	// poll each authz to wait for completion of all challenges
	for _, authz := range authzStates {
		err = c.pollAuthorization(ctx, account, authz, failedChallengeTypes)
		if err != nil {
			return err
		}
	}

	return nil
}

func buildUAString() string {
	ua := "CertMagic"
	if UserAgent != "" {
		ua = UserAgent + " " + ua
	}
	return ua
}

// Some default values passed down to the underlying ZeroSSL client.
var (
	UserAgent   string
	HTTPTimeout = 30 * time.Second
)

type validationState struct {
	identifier          Identifier
	validation          IdentifierValidation
	challenges          []Challenge
	currentChallenge    Challenge
	currentSolver       Solver
	remainingChallenges []Challenge
}

func (v validationState) listOfferedChallenges() []string {
	return challengeTypeNames(v.challenges)
}

func (v validationState) listRemainingChallenges() []string {
	return challengeTypeNames(v.remainingChallenges)
}

func challengeTypeNames(challengeList []Challenge) []string {
	names := make([]string, 0, len(challengeList))
	for _, chal := range challengeList {
		names = append(names, string(chal.Type))
	}
	return names
}

// challengeHistory is a memory of how successful a challenge type is.
type challengeHistory struct {
	typeName         string
	successes, total int
}

func (ch challengeHistory) successRatio() float64 {
	if ch.total == 0 {
		return 1.0
	}
	return float64(ch.successes) / float64(ch.total)
}

// failedChallengeMap keeps track of failed challenge types per identifier.
type failedChallengeMap map[string][]string

func (fcm failedChallengeMap) rememberFailedChallenge(v *validationState) {
	idKey := fcm.idKey(v)
	fcm[idKey] = append(fcm[idKey], string(v.currentChallenge.Type))
}

// enqueueUnfailedChallenges enqueues each challenge offered in authz if it
// is not known to have failed for the authz's identifier already.
func (fcm failedChallengeMap) enqueueUnfailedChallenges(v *validationState) {
	idKey := fcm.idKey(v)
	for _, chal := range v.challenges {
		if !contains(fcm[idKey], string(chal.Type)) {
			v.remainingChallenges = append(v.remainingChallenges, chal)
		}
	}
}

func (fcm failedChallengeMap) idKey(v *validationState) string {
	return v.Identifier.Type + v.IdentifierValue()
}

// challengeTypes is a list of challenges we've seen and/or
// used previously. It sorts from most successful to least
// successful, such that most successful challenges are first.
type challengeTypes []challengeHistory

// Len is part of sort.Interface.
func (ct challengeTypes) Len() int { return len(ct) }

// Swap is part of sort.Interface.
func (ct challengeTypes) Swap(i, j int) { ct[i], ct[j] = ct[j], ct[i] }

// Less is part of sort.Interface. It sorts challenge
// types from highest success ratio to lowest.
func (ct challengeTypes) Less(i, j int) bool {
	return ct[i].successRatio() > ct[j].successRatio()
}

func (ct *challengeTypes) addUnique(challengeType string) {
	for _, c := range *ct {
		if c.typeName == challengeType {
			return
		}
	}
	*ct = append(*ct, challengeHistory{typeName: challengeType})
}

func (ct challengeTypes) increment(challengeType string, successful bool) {
	defer sort.Stable(ct) // keep most successful challenges in front
	for i, c := range ct {
		if c.typeName == challengeType {
			ct[i].total++
			if successful {
				ct[i].successes++
			}
			return
		}
	}
}

func contains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}

// retryableErr wraps an error that indicates the caller should retry
// the operation; specifically with a different challenge type.
type retryableErr struct{ error }

func (re retryableErr) Unwrap() error { return re.error }

// Keep a list of challenges we've seen offered by servers, ordered by success rate.
var (
	preferredChallenges   challengeTypes
	preferredChallengesMu sync.Mutex
)

// Best practice is to avoid the default RNG source and seed our own;
// custom sources are not safe for concurrent use, hence the mutex.
var (
	randomSource   = weakrand.New(weakrand.NewSource(time.Now().UnixNano()))
	randomSourceMu sync.Mutex
)
