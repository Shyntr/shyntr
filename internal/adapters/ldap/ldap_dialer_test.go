package ldap_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	ldapadapter "github.com/Shyntr/shyntr/internal/adapters/ldap"
	"github.com/Shyntr/shyntr/internal/domain/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

// osixia/openldap:1.5.0 defaults:
//   admin DN   : cn=admin,dc=example,dc=org
//   admin pw   : admin
//   base DN    : dc=example,dc=org
//   LDAP port  : 389 (mapped to a random host port)

const (
	ldapImage   = "osixia/openldap:1.5.0"
	ldapPort    = "389/tcp"
	ldapAdminDN = "cn=admin,dc=example,dc=org"
	ldapAdminPW = "admin"
	ldapBaseDN  = "dc=example,dc=org"
)

func startOpenLDAP(t *testing.T) (host string, port string) {
	t.Helper()
	if testing.Short() {
		t.Skip("requires Docker")
	}
	ctx := context.Background()

	req := testcontainers.ContainerRequest{
		Image:        ldapImage,
		ExposedPorts: []string{ldapPort},
		Env: map[string]string{
			"LDAP_ORGANISATION":   "Example Inc.",
			"LDAP_DOMAIN":         "example.org",
			"LDAP_ADMIN_PASSWORD": ldapAdminPW,
		},
		// osixia logs "slapd starting" once slapd is ready.
		WaitingFor: wait.ForLog("slapd starting").
			WithStartupTimeout(90 * time.Second),
	}

	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	require.NoError(t, err)

	t.Cleanup(func() { _ = container.Terminate(context.Background()) })

	h, err := container.Host(ctx)
	require.NoError(t, err)

	p, err := container.MappedPort(ctx, ldapPort)
	require.NoError(t, err)

	return h, p.Port()
}

func TestLDAPDialer_AnonymousBind(t *testing.T) {
	host, port := startOpenLDAP(t)
	dialer := ldapadapter.NewLDAPDialer()

	conn := &model.LDAPConnection{
		ServerURL: fmt.Sprintf("ldap://%s:%s", host, port),
		BaseDN:    ldapBaseDN,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	session, err := dialer.Dial(ctx, conn)
	require.NoError(t, err, "anonymous dial must succeed")
	require.NotNil(t, session)
	assert.NoError(t, session.Close())
}

func TestLDAPDialer_ServiceAccountBind(t *testing.T) {
	host, port := startOpenLDAP(t)
	dialer := ldapadapter.NewLDAPDialer()

	conn := &model.LDAPConnection{
		ServerURL:    fmt.Sprintf("ldap://%s:%s", host, port),
		BindDN:       ldapAdminDN,
		BindPassword: ldapAdminPW,
		BaseDN:       ldapBaseDN,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	session, err := dialer.Dial(ctx, conn)
	require.NoError(t, err, "service account bind must succeed with correct credentials")
	require.NotNil(t, session)
	assert.NoError(t, session.Close())
}

func TestLDAPDialer_WrongPassword_ReturnsError(t *testing.T) {
	host, port := startOpenLDAP(t)
	dialer := ldapadapter.NewLDAPDialer()

	conn := &model.LDAPConnection{
		ServerURL:    fmt.Sprintf("ldap://%s:%s", host, port),
		BindDN:       ldapAdminDN,
		BindPassword: "wrong-password",
		BaseDN:       ldapBaseDN,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	session, err := dialer.Dial(ctx, conn)
	assert.Error(t, err, "Dial must return error for invalid credentials")
	assert.Nil(t, session)
	// Password must not appear in the error message.
	assert.NotContains(t, err.Error(), "wrong-password",
		"error message must not leak the bind password")
}

func TestLDAPDialer_Search_FindsAdminEntry(t *testing.T) {
	host, port := startOpenLDAP(t)
	dialer := ldapadapter.NewLDAPDialer()

	conn := &model.LDAPConnection{
		ServerURL:    fmt.Sprintf("ldap://%s:%s", host, port),
		BindDN:       ldapAdminDN,
		BindPassword: ldapAdminPW,
		BaseDN:       ldapBaseDN,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	session, err := dialer.Dial(ctx, conn)
	require.NoError(t, err)
	defer session.Close()

	// The base object itself always exists.
	entries, err := session.Search(ctx, "(objectClass=*)", []string{"dn"})
	require.NoError(t, err)
	assert.NotEmpty(t, entries, "search must return at least the base DN entry")
}

func TestLDAPDialer_Authenticate_AdminUser(t *testing.T) {
	host, port := startOpenLDAP(t)
	dialer := ldapadapter.NewLDAPDialer()

	conn := &model.LDAPConnection{
		ServerURL:    fmt.Sprintf("ldap://%s:%s", host, port),
		BindDN:       ldapAdminDN,
		BindPassword: ldapAdminPW,
		BaseDN:       ldapBaseDN,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	session, err := dialer.Dial(ctx, conn)
	require.NoError(t, err)
	defer session.Close()

	// Correct password.
	err = session.Authenticate(ctx, ldapAdminDN, ldapAdminPW)
	assert.NoError(t, err, "authentication with correct password must succeed")

	// Wrong password.
	err = session.Authenticate(ctx, ldapAdminDN, "wrongpass")
	assert.Error(t, err, "authentication with wrong password must fail")
}

func TestLDAPDialer_ContextCancellation(t *testing.T) {
	host, port := startOpenLDAP(t)
	dialer := ldapadapter.NewLDAPDialer()

	conn := &model.LDAPConnection{
		ServerURL: fmt.Sprintf("ldap://%s:%s", host, port),
		BaseDN:    ldapBaseDN,
	}

	// Cancel immediately — must not panic, may succeed or return ctx error.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	session, err := dialer.Dial(ctx, conn)
	if err != nil {
		assert.Nil(t, session)
	} else if session != nil {
		_ = session.Close()
	}
}
