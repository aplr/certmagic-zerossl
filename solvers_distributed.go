package zerossl

import (
	"context"
	"encoding/json"
	"fmt"
	"path"

	"github.com/caddyserver/certmagic"
)

// distributedSolver allows the HTTP challenge to be solved
// by an instance other than the one which initiated it.
// This is useful behind load balancers or in other cluster/fleet
// configurations. The only requirement is that the instance which
// initiates the challenge shares the same storage and locker with
// the others in the cluster. The storage backing the certificate
// cache in distributedSolver.config is crucial.
//
// Obviously, the instance which completes the challenge must be
// serving on the HTTPChallengePort for the HTTP challenge (or have all
// the packets port-forwarded) to receive and handle the request. The
// server which receives the challenge must handle it by checking to
// see if the challenge token exists in storage, and if so, decode it
// and use it to serve up the correct response. HTTPChallengeHandler
// in this package as well as the GetCertificate method implemented
// by a Config support and even require this behavior.
//
// In short: the only two requirements for cluster operation are
// sharing sync and storage, and using the facilities provided by
// this package for solving the challenges.
type distributedSolver struct {
	// The storage backing the distributed solver. It must be
	// the same storage configuration as what is solving the
	// challenge in order to be effective.
	storage certmagic.Storage

	// The storage key prefix, associated with the issuer
	// that is solving the challenge.
	storageKeyIssuerPrefix string

	// The underlying solver to use to solve the challenge.
	solver Solver
}

// Present invokes the underlying solver's Present method
// and also stores domain, token, and keyAuth to the storage
// backing the certificate cache of ds.issuer.
func (ds distributedSolver) Present(ctx context.Context, chal Challenge) error {
	infoBytes, err := json.Marshal(chal)
	if err != nil {
		return err
	}

	err = ds.storage.Store(ctx, ds.challengeTokensKey(challengeKey(chal)), infoBytes)
	if err != nil {
		return err
	}

	err = ds.solver.Present(ctx, chal)
	if err != nil {
		return fmt.Errorf("presenting with embedded solver: %v", err)
	}

	return nil
}

// Wait wraps the underlying solver's Wait() method, if any. Implements Waiter.
func (ds distributedSolver) Wait(ctx context.Context, challenge Challenge) error {
	if waiter, ok := ds.solver.(Waiter); ok {
		return waiter.Wait(ctx, challenge)
	}
	return nil
}

// CleanUp invokes the underlying solver's CleanUp method
// and also cleans up any assets saved to storage.
func (ds distributedSolver) CleanUp(ctx context.Context, chal Challenge) error {
	err := ds.storage.Delete(ctx, ds.challengeTokensKey(challengeKey(chal)))
	if err != nil {
		return err
	}
	err = ds.solver.CleanUp(ctx, chal)
	if err != nil {
		return fmt.Errorf("cleaning up embedded provider: %v", err)
	}
	return nil
}

// challengeTokensPrefix returns the key prefix for challenge info.
func (ds distributedSolver) challengeTokensPrefix() string {
	return path.Join(ds.storageKeyIssuerPrefix, "challenge_tokens")
}

// challengeTokensKey returns the key to use to store and access
// challenge info for domain.
func (ds distributedSolver) challengeTokensKey(domain string) string {
	return path.Join(ds.challengeTokensPrefix(), certmagic.StorageKeys.Safe(domain)+".json")
}

// challengeKey returns the map key for a given challenge, which is the identifier
func challengeKey(chal Challenge) string {
	return chal.Identifier.Value
}
