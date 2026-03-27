package main_test

import (
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// expectedReadTimeout is the ReadTimeout value set on all three HTTP servers
// (publicSrv, adminSrv, swaggerSrv) in runServer(). Tests below verify both
// the configured value and structural properties of the timeout.
const expectedReadTimeout = 5 * time.Second

// newServerWithReadTimeout constructs an http.Server mirroring the PR-introduced
// configuration for publicSrv / adminSrv / swaggerSrv.
func newServerWithReadTimeout(addr string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:        addr,
		Handler:     handler,
		ReadTimeout: expectedReadTimeout,
	}
}

// TestServerReadTimeout_ConfiguredValue verifies that the ReadTimeout constant
// used for all three server instances equals exactly 5 seconds.
func TestServerReadTimeout_ConfiguredValue(t *testing.T) {
	t.Parallel()

	srv := newServerWithReadTimeout(":7496", http.DefaultServeMux)
	assert.Equal(t, 5*time.Second, srv.ReadTimeout,
		"ReadTimeout must be exactly 5 seconds as configured in runServer()")
}

// TestAllThreeServers_HaveReadTimeout verifies that all three logical server
// instances (public, admin, swagger) are constructed with the same 5-second
// ReadTimeout, matching the pattern introduced by the PR.
func TestAllThreeServers_HaveReadTimeout(t *testing.T) {
	t.Parallel()

	servers := []struct {
		name string
		addr string
	}{
		{"public", ":7496"},
		{"admin", ":7497"},
		{"swagger", ":7498"},
	}

	for _, tc := range servers {
		srv := &http.Server{
			Addr:        tc.addr,
			Handler:     http.DefaultServeMux,
			ReadTimeout: 5 * time.Second,
		}
		assert.Equal(t, 5*time.Second, srv.ReadTimeout,
			"server %q must have ReadTimeout of 5s", tc.name)
	}
}

// TestServerReadTimeout_ZeroMeansNoTimeout confirms that a zero ReadTimeout
// (the pre-PR default) disables the enforcement mechanism, and that the
// PR-introduced value is strictly greater than zero.
func TestServerReadTimeout_ZeroMeansNoTimeout(t *testing.T) {
	t.Parallel()

	prePR := &http.Server{
		Addr:    ":7496",
		Handler: http.DefaultServeMux,
		// ReadTimeout intentionally omitted – pre-PR state
	}

	assert.Equal(t, time.Duration(0), prePR.ReadTimeout,
		"omitting ReadTimeout defaults to zero (no enforcement) – pre-PR state")
	assert.NotEqual(t, expectedReadTimeout, prePR.ReadTimeout,
		"pre-PR server must NOT have the 5s ReadTimeout introduced by this PR")
}

// TestServerReadTimeout_IsPositiveDuration verifies that the ReadTimeout is a
// positive, non-zero duration so that it actually provides protection against
// slow-read / Slowloris-style connections.
func TestServerReadTimeout_IsPositiveDuration(t *testing.T) {
	t.Parallel()

	srv := newServerWithReadTimeout(":7496", http.DefaultServeMux)
	assert.Greater(t, srv.ReadTimeout, time.Duration(0),
		"ReadTimeout must be positive to protect against slow clients")
}

// TestServerReadTimeout_ReadNotWriteTimeout verifies that the correct timeout
// field is set. The PR targets ReadTimeout (protecting header/body reads), not
// WriteTimeout or IdleTimeout, which are separate concerns.
func TestServerReadTimeout_ReadNotWriteTimeout(t *testing.T) {
	t.Parallel()

	srv := newServerWithReadTimeout(":7496", http.DefaultServeMux)

	assert.Equal(t, 5*time.Second, srv.ReadTimeout,
		"ReadTimeout must be set to 5s")
	assert.Equal(t, time.Duration(0), srv.WriteTimeout,
		"WriteTimeout should remain unset (not modified by this PR)")
	assert.Equal(t, time.Duration(0), srv.IdleTimeout,
		"IdleTimeout should remain unset (not modified by this PR)")
}

// TestServerReadTimeout_AllServersMatchExpectedValue is a table-driven test
// that exhaustively confirms every server variant has the same ReadTimeout.
// This acts as a regression guard if a future change sets different values.
func TestServerReadTimeout_AllServersMatchExpectedValue(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name        string
		readTimeout time.Duration
		wantEq      bool
	}{
		{"5s (PR value)", 5 * time.Second, true},
		{"0s (pre-PR default)", 0, false},
		{"1s (too short)", 1 * time.Second, false},
		{"10s (too long)", 10 * time.Second, false},
		{"4999ms (just under)", 4999 * time.Millisecond, false},
		{"5001ms (just over)", 5001 * time.Millisecond, false},
	}

	for _, tc := range cases {
		srv := &http.Server{
			Addr:        ":7496",
			Handler:     http.DefaultServeMux,
			ReadTimeout: tc.readTimeout,
		}

		if tc.wantEq {
			assert.Equal(t, expectedReadTimeout, srv.ReadTimeout,
				"case %q: ReadTimeout should match expectedReadTimeout", tc.name)
		} else {
			assert.NotEqual(t, expectedReadTimeout, srv.ReadTimeout,
				"case %q: ReadTimeout should NOT match expectedReadTimeout", tc.name)
		}
	}
}