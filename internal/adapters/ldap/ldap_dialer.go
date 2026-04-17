package ldap

import (
	"context"
	"crypto/tls"
	"fmt"

	"github.com/Shyntr/shyntr/internal/application/port"
	"github.com/Shyntr/shyntr/internal/domain/model"
	ldaplib "github.com/go-ldap/ldap/v3"
	"golang.org/x/sync/semaphore"
)

// defaultMaxConcurrent is the maximum number of simultaneous LDAP connections
// the pool will allow. Callers that exceed this limit block until a slot frees
// or the context is cancelled.
const defaultMaxConcurrent = 20

type ldapDialer struct {
	sem *semaphore.Weighted
}

// NewLDAPDialer returns an LDAPDialer backed by a goroutine pool that caps
// concurrent in-flight LDAP connections at defaultMaxConcurrent.
// All blocking I/O is dispatched to a worker goroutine so the calling
// goroutine (Gin handler) is never blocked directly.
func NewLDAPDialer() port.LDAPDialer {
	return &ldapDialer{
		sem: semaphore.NewWeighted(defaultMaxConcurrent),
	}
}

// Dial acquires a slot from the pool, then connects and binds to the LDAP
// server in a worker goroutine. The returned session's Close() method releases
// the pool slot. If ctx is cancelled before the dial completes, a background
// goroutine drains and closes the underlying connection.
func (d *ldapDialer) Dial(ctx context.Context, conn *model.LDAPConnection) (port.LDAPSession, error) {
	if err := d.sem.Acquire(ctx, 1); err != nil {
		return nil, fmt.Errorf("ldap: connection pool full: %w", err)
	}

	type dialResult struct {
		session *ldapSession
		err     error
	}
	ch := make(chan dialResult, 1)

	go func() {
		s, err := d.dialInternal(conn)
		ch <- dialResult{s, err}
	}()

	select {
	case r := <-ch:
		if r.err != nil {
			d.sem.Release(1)
			return nil, r.err
		}
		// session.Close() is responsible for releasing the semaphore slot.
		r.session.release = func() { d.sem.Release(1) }
		return r.session, nil

	case <-ctx.Done():
		// Context cancelled before the dial completed. The goroutine may still
		// succeed; we drain it in the background and clean up.
		go func() {
			r := <-ch
			if r.session != nil {
				_ = r.session.l.Close()
			}
			d.sem.Release(1)
		}()
		return nil, ctx.Err()
	}
}

// dialInternal performs the blocking TCP connect, optional StartTLS negotiation,
// and service-account bind. Called exclusively from a worker goroutine.
// BindPassword is never logged.
func (d *ldapDialer) dialInternal(conn *model.LDAPConnection) (*ldapSession, error) {
	var opts []ldaplib.DialOpt
	if conn.TLSInsecureSkipVerify {
		opts = append(opts, ldaplib.DialWithTLSConfig(&tls.Config{
			InsecureSkipVerify: true, //nolint:gosec // user-controlled flag
			MinVersion:         tls.VersionTLS12,
		}))
	}

	l, err := ldaplib.DialURL(conn.ServerURL, opts...)
	if err != nil {
		return nil, fmt.Errorf("ldap: dial %s: %w", conn.ServerURL, err)
	}

	if conn.StartTLS {
		tlsCfg := &tls.Config{
			InsecureSkipVerify: conn.TLSInsecureSkipVerify, //nolint:gosec
			MinVersion:         tls.VersionTLS12,
		}
		if err := l.StartTLS(tlsCfg); err != nil {
			_ = l.Close()
			return nil, fmt.Errorf("ldap: StartTLS: %w", err)
		}
	}

	if conn.BindDN != "" {
		// BindPassword deliberately not included in any error message.
		if err := l.Bind(conn.BindDN, conn.BindPassword); err != nil {
			_ = l.Close()
			return nil, fmt.Errorf("ldap: service account bind failed for dn %q: %w", conn.BindDN, err)
		}
	}

	return &ldapSession{l: l, baseDN: conn.BaseDN}, nil
}

// ldapSession wraps an active *ldaplib.Conn and exposes the port.LDAPSession contract.
type ldapSession struct {
	l       *ldaplib.Conn
	baseDN  string
	release func() // called once in Close() to return the pool slot
}

// Authenticate binds as userDN with the supplied password to verify credentials.
// The password is never logged. Callers are expected to Close the session after
// credential verification; this flow does not rebind to the service account.
func (s *ldapSession) Authenticate(ctx context.Context, userDN, password string) error {
	type result struct{ err error }
	ch := make(chan result, 1)
	go func() {
		ch <- result{err: s.l.Bind(userDN, password)}
	}()
	select {
	case r := <-ch:
		return r.err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Search executes a whole-subtree LDAP search under the session's base DN.
func (s *ldapSession) Search(ctx context.Context, filter string, attrs []string) ([]model.LDAPEntry, error) {
	type result struct {
		entries []model.LDAPEntry
		err     error
	}
	ch := make(chan result, 1)
	go func() {
		req := ldaplib.NewSearchRequest(
			s.baseDN,
			ldaplib.ScopeWholeSubtree,
			ldaplib.NeverDerefAliases,
			0, 0, false,
			filter, attrs, nil,
		)
		sr, err := s.l.Search(req)
		if err != nil {
			ch <- result{nil, err}
			return
		}
		entries := make([]model.LDAPEntry, 0, len(sr.Entries))
		for _, e := range sr.Entries {
			entry := model.LDAPEntry{
				DN:         e.DN,
				Attributes: make(map[string][]string, len(e.Attributes)),
			}
			for _, attr := range e.Attributes {
				entry.Attributes[attr.Name] = attr.Values
			}
			entries = append(entries, entry)
		}
		ch <- result{entries, nil}
	}()
	select {
	case r := <-ch:
		return r.entries, r.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// Close closes the underlying TCP connection and releases the pool slot.
// Safe to call multiple times.
func (s *ldapSession) Close() error {
	if s.l != nil {
		_ = s.l.Close()
	}
	if s.release != nil {
		s.release()
		s.release = nil
	}
	return nil
}
