package zerossl

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"strings"
	"sync"

	"github.com/caddyserver/certmagic"
	"go.uber.org/zap"
)

func (iss *APIIssuer) HTTPChallengeHandler(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if iss.HandleHTTPChallenge(w, r) {
			return
		}
		h.ServeHTTP(w, r)
	})
}

func (iss *APIIssuer) HandleHTTPChallenge(w http.ResponseWriter, r *http.Request) bool {
	if iss == nil {
		return false
	}
	if iss.DisableHTTPChallenge {
		return false
	}
	if !looksLikeHTTPChallenge(r) {
		return false
	}
	return iss.distributedHTTPChallengeSolver(w, r)
}

func (iss *APIIssuer) distributedHTTPChallengeSolver(
	w http.ResponseWriter,
	r *http.Request,
) bool {
	if iss == nil {
		return false
	}

	host := hostOnly(r.Host)

	challenge, distributed, err := getDistributedChallengeInfo(r.Context(), iss.config, host)
	if err != nil {
		iss.Logger.With(
			zap.String("host", host),
			zap.String("remote_addr", r.RemoteAddr),
			zap.String("user_agent", r.Header.Get("User-Agent")),
			zap.Error(err),
		).Error("looking up info for HTTP challenge")
		return false
	}

	return solveHTTPChallenge(iss.Logger, w, r, challenge, distributed)
}

func solveHTTPChallenge(
	logger *zap.Logger,
	w http.ResponseWriter,
	r *http.Request,
	challenge Challenge,
	distributed bool,
) bool {
	challengeReqPath := challenge.HTTPResourcePath
	hostMatches := strings.EqualFold(hostOnly(r.Host), challenge.Identifier.Value)

	if r.Method == "GET" && r.URL.Path == challengeReqPath && hostMatches {
		w.Header().Add("Content-Type", "text/plain")
		w.Write([]byte(strings.Join(challenge.HTTPResourcePayload, "\n")))
		r.Close = true
		logger.With(
			zap.String("identifier", challenge.Identifier.Value),
			zap.String("challenge", "http-01"),
			zap.String("remote", r.RemoteAddr),
			zap.Bool("distributed", distributed),
		).Info("served key authentication")
		return true
	}

	return false
}

func getDistributedChallengeInfo(
	ctx context.Context,
	cfg *certmagic.Config,
	identifier string,
) (Challenge, bool, error) {
	// first, check if our process initiated this challenge; if so, just return it
	chalData, ok := getLocalChallenge(identifier)
	if ok {
		return chalData, false, nil
	}

	// otherwise, perhaps another instance in the cluster initiated it; check
	// the configured storage to retrieve challenge data

	var chal Challenge
	var chalBytes []byte
	var tokenKey string

	for _, issuer := range cfg.Issuers {
		ds := distributedSolver{
			storage:                cfg.Storage,
			storageKeyIssuerPrefix: storageKeyCAPrefix(issuer.IssuerKey()),
		}
		tokenKey = ds.challengeTokensKey(identifier)
		var err error
		chalBytes, err = cfg.Storage.Load(ctx, tokenKey)
		if err == nil {
			break
		}
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		return Challenge{}, false, fmt.Errorf("opening distributed challenge token file %s: %v", tokenKey, err)
	}

	if len(chalBytes) == 0 {
		return Challenge{}, false, fmt.Errorf("no information found to solve challenge for identifier: %s", identifier)
	}

	err := json.Unmarshal(chalBytes, &chal)
	if err != nil {
		return Challenge{}, false, fmt.Errorf("decoding challenge token file %s (corrupted?): %v", tokenKey, err)
	}

	return chal, true, nil
}

func getLocalChallenge(identifier string) (Challenge, bool) {
	activeChallengesMu.Lock()
	chalData, ok := activeChallenges[identifier]
	activeChallengesMu.Unlock()
	return chalData, ok
}

var (
	activeChallenges   = make(map[string]Challenge)
	activeChallengesMu sync.Mutex
)

func looksLikeHTTPChallenge(r *http.Request) bool {
	return r.Method == "GET" && strings.HasPrefix(r.URL.Path, challengeBasePath)
}

// .well-known/pki-validation/2449B.txt
const challengeBasePath = "/.well-known/pki-validation"
