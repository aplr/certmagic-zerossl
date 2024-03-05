package zerossl

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// httpSolver solves the HTTP challenge. It must be
// associated with a config and an address to use
// for solving the challenge. If multiple httpSolvers
// are initialized concurrently, the first one to
// begin will start the server, and the last one to
// finish will stop the server. This solver must be
// wrapped by a distributedSolver to work properly,
// because the only way the HTTP challenge handler
// can access the keyAuth material is by loading it
// from storage, which is done by distributedSolver.
type httpSolver struct {
	closed  int32 // accessed atomically
	issuer  *APIIssuer
	address string
}

// Present starts an HTTP server if none is already listening on s.address.
func (s *httpSolver) Present(ctx context.Context, _ Challenge) error {
	solversMu.Lock()
	defer solversMu.Unlock()

	si := getSolverInfo(s.address)
	si.count++
	if si.listener != nil {
		return nil // already be served by us
	}

	// notice the unusual error handling here; we
	// only continue to start a challenge server if
	// we got a listener; in all other cases return
	ln, err := robustTryListen(s.address)
	if ln == nil {
		return err
	}

	// successfully bound socket, so save listener and start key auth HTTP server
	si.listener = ln
	go s.serve(ctx, si)

	return nil
}

// serve is an HTTP server that serves only HTTP challenge responses.
func (s *httpSolver) serve(ctx context.Context, si *solverInfo) {
	defer func() {
		if err := recover(); err != nil {
			buf := make([]byte, stackTraceBufferSize)
			buf = buf[:runtime.Stack(buf, false)]
			log.Printf("panic: http solver server: %v\n%s", err, buf)
		}
	}()
	defer close(si.done)
	httpServer := &http.Server{
		Handler:     s.issuer.HTTPChallengeHandler(http.NewServeMux()),
		BaseContext: func(listener net.Listener) context.Context { return ctx },
	}
	httpServer.SetKeepAlivesEnabled(false)
	err := httpServer.Serve(si.listener)
	if err != nil && atomic.LoadInt32(&s.closed) != 1 {
		log.Printf("[ERROR] key auth HTTP server: %v", err)
	}
}

// CleanUp cleans up the HTTP server if it is the last one to finish.
func (s *httpSolver) CleanUp(_ context.Context, _ Challenge) error {
	solversMu.Lock()
	defer solversMu.Unlock()
	si := getSolverInfo(s.address)
	si.count--
	if si.count == 0 {
		// last one out turns off the lights
		atomic.StoreInt32(&s.closed, 1)
		if si.listener != nil {
			si.listener.Close()
			<-si.done
		}
		delete(solvers, s.address)
	}
	return nil
}

// solverInfo associates a listener with the
// number of challenges currently using it.
type solverInfo struct {
	closed   int32 // accessed atomically
	count    int
	listener net.Listener
	done     chan struct{} // used to signal when our own solver server is done
}

// getSolverInfo gets a valid solverInfo struct for address.
func getSolverInfo(address string) *solverInfo {
	si, ok := solvers[address]
	if !ok {
		si = &solverInfo{done: make(chan struct{})}
		solvers[address] = si
	}
	return si
}

// robustTryListen calls net.Listen for a TCP socket at addr.
// This function may return both a nil listener and a nil error!
// If it was able to bind the socket, it returns the listener
// and no error. If it wasn't able to bind the socket because
// the socket is already in use, then it returns a nil listener
// and nil error. If it had any other error, it returns the
// error. The intended error handling logic for this function
// is to proceed if the returned listener is not nil; otherwise
// return err (which may also be nil). In other words, this
// function ignores errors if the socket is already in use,
// which is useful for our challenge servers, where we assume
// that whatever is already listening can solve the challenges.
func robustTryListen(addr string) (net.Listener, error) {
	var listenErr error
	for i := 0; i < 2; i++ {
		// doesn't hurt to sleep briefly before the second
		// attempt in case the OS has timing issues
		if i > 0 {
			time.Sleep(100 * time.Millisecond)
		}

		// if we can bind the socket right away, great!
		var ln net.Listener
		ln, listenErr = net.Listen("tcp", addr)
		if listenErr == nil {
			return ln, nil
		}

		// if it failed just because the socket is already in use, we
		// have no choice but to assume that whatever is using the socket
		// can answer the challenge already, so we ignore the error
		connectErr := dialTCPSocket(addr)
		if connectErr == nil {
			return nil, nil
		}

		// Hmm, we couldn't connect to the socket, so something else must
		// be wrong, right? wrong!! Apparently if a port is bound by another
		// listener with a specific host, i.e. 'x:1234', we cannot bind to
		// ':1234' -- it is considered a conflict, but 'y:1234' is not.
		// I guess we need to assume the conflicting listener is properly
		// configured and continue. But we should tell the user to specify
		// the correct ListenHost to avoid conflict or at least so we can
		// know that the user is intentional about that port and hopefully
		// has an ZeroSSL solver on it.
		//
		// History:
		// https://caddy.community/t/caddy-retry-error/7317
		// https://caddy.community/t/v2-upgrade-to-caddy2-failing-with-errors/7423
		// https://github.com/caddyserver/certmagic/issues/250
		if strings.Contains(listenErr.Error(), "address already in use") ||
			strings.Contains(listenErr.Error(), "one usage of each socket address") {
			log.Printf("[WARNING] %v - be sure to set the APIIssuer.ListenHost field; assuming conflicting listener is correctly configured and continuing", listenErr)
			return nil, nil
		}
	}
	return nil, fmt.Errorf("could not start listener for challenge server at %s: %v", addr, listenErr)
}

// dialTCPSocket connects to a TCP address just for the sake of
// seeing if it is open. It returns a nil error if a TCP connection
// can successfully be made to addr within a short timeout.
func dialTCPSocket(addr string) error {
	conn, err := net.DialTimeout("tcp", addr, 250*time.Millisecond)
	if err == nil {
		conn.Close()
	}
	return err
}

// The active challenge solvers, keyed by listener address,
// and protected by a mutex. Note that the creation of
// solver listeners and the incrementing of their counts
// are atomic operations guarded by this mutex.
var (
	solvers   = make(map[string]*solverInfo)
	solversMu sync.Mutex
)

const stackTraceBufferSize = 1024 * 128
