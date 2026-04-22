package port

import (
	"context"

	"github.com/Shyntr/shyntr/internal/domain/model"
)

// LDAPSession represents an established, service-account-bound LDAP connection.
// Callers must call Close() when done to release the underlying TCP connection
// and return the slot to the goroutine pool.
type LDAPSession interface {
	// Authenticate performs a bind as userDN with the supplied password.
	// The password is never logged.
	Authenticate(ctx context.Context, userDN, password string) error
	// Search executes an LDAP search under the session's base DN.
	Search(ctx context.Context, filter string, attrs []string) ([]model.LDAPEntry, error)
	// Close releases the connection back to the goroutine pool.
	Close() error
}

// LDAPDialer opens an authenticated LDAP session for a given LDAPConnection.
// Implementations must never block the calling goroutine directly; all blocking
// I/O must happen inside a worker goroutine (goroutine pool) and be cancellable
// via the provided context.
type LDAPDialer interface {
	Dial(ctx context.Context, conn *model.LDAPConnection) (LDAPSession, error)
}
