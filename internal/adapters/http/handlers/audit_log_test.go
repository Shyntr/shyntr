package handlers_test

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Shyntr/shyntr/config"
	auditpkg "github.com/Shyntr/shyntr/internal/adapters/audit"
	"github.com/Shyntr/shyntr/internal/adapters/http/handlers"
	"github.com/Shyntr/shyntr/internal/adapters/persistence"
	"github.com/Shyntr/shyntr/internal/adapters/persistence/models"
	"github.com/Shyntr/shyntr/internal/adapters/persistence/repository"
	"github.com/Shyntr/shyntr/internal/application/usecase"
	"github.com/Shyntr/shyntr/pkg/logger"
	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"gorm.io/gorm"
)

// AuditLogEntry mirrors the structured fields emitted by AuditLogger.Log via Zap.
type AuditLogEntry struct {
	Msg             string `json:"msg"`
	Event           string `json:"event"`
	TenantID        string `json:"tenant_id"`
	UserIdentifier  string `json:"user_identifier"`
	ClientIP        string `json:"client_ip"`
	RelyingPartyURL string `json:"relying_party_url"`
}

// setupTC06482 creates an isolated in-memory database, a Zap logger backed by a
// bytes.Buffer, and an AdminHandler wired together so that audit events are
// captured in the buffer instead of (only) being written to the DB.
func setupTC06482(t *testing.T) (*gin.Engine, *bytes.Buffer, *gorm.DB) {
	t.Helper()

	// Ensure the global logger is initialized (needed by logger.FromGin inside handlers).
	logger.InitLogger("info")

	// Build a Zap logger that writes JSON to an in-memory buffer so the test can
	// assert audit event fields without touching real I/O.
	buf := &bytes.Buffer{}
	encoderCfg := zapcore.EncoderConfig{
		MessageKey:     "msg",
		LevelKey:       "level",
		TimeKey:        "ts",
		EncodeLevel:    zapcore.LowercaseLevelEncoder,
		EncodeTime:     zapcore.EpochTimeEncoder,
		EncodeDuration: zapcore.StringDurationEncoder,
	}
	core := zapcore.NewCore(
		zapcore.NewJSONEncoder(encoderCfg),
		zapcore.AddSync(buf),
		zapcore.InfoLevel,
	)
	testLog := zap.New(core)

	// Open a per-test SQLite database to avoid collisions between parallel tests.
	dbName := fmt.Sprintf("file:tc06482_%d?mode=memory&cache=shared", time.Now().UnixNano())
	db, err := gorm.Open(sqlite.Open(dbName), &gorm.Config{})
	require.NoError(t, err, "open in-memory db")
	require.NoError(t, persistence.MigrateDB(db), "migrate db")

	// Seed a login request for the success scenario.
	db.Create(&models.LoginRequestGORM{
		ID:         "challenge-accept-tc06482",
		TenantID:   "tenant-tc06482",
		ClientID:   "client-tc06482",
		Subject:    "user-alice",
		RequestURL: "http://localhost/oauth2/auth?client_id=client-tc06482",
		Active:     true,
	})

	// Seed a login request for the failure (reject) scenario – subject is set so
	// that the audit user_identifier assertion passes even on rejection.
	db.Create(&models.LoginRequestGORM{
		ID:         "challenge-reject-tc06482",
		TenantID:   "tenant-tc06482",
		ClientID:   "client-tc06482",
		Subject:    "user-bob",
		RequestURL: "http://localhost/oauth2/auth?client_id=client-tc06482",
		Active:     true,
	})

	cfg := &config.Config{
		AppSecret:     "12345678901234567890123456789012",
		BaseIssuerURL: "http://localhost:7496",
	}

	requestRepository := repository.NewAuthRequestRepository(db)
	auditLogger := auditpkg.NewAuditLoggerWithZap(db, testLog)
	authUseCase := usecase.NewAuthUseCase(requestRepository, auditLogger)

	var tenantUC usecase.TenantUseCase       // nil – not called by accept/reject
	var clientUC usecase.OAuth2ClientUseCase // nil – not called by accept/reject
	adminHandler := handlers.NewAdminHandler(tenantUC, clientUC, authUseCase, cfg)

	gin.SetMode(gin.TestMode)
	r := gin.New()
	// Disable proxy trust so that c.ClientIP() reads directly from RemoteAddr.
	// Tests set req.RemoteAddr = "10.20.30.40:12345" to control the reported IP.
	_ = r.SetTrustedProxies([]string{})
	r.PUT("/admin/login/accept", adminHandler.AcceptLoginRequest)
	r.PUT("/admin/login/reject", adminHandler.RejectLoginRequest)

	return r, buf, db
}

// parseAuditEvents scans each JSON line in the buffer and returns all entries
// whose "msg" field equals "audit.event".
func parseAuditEvents(t *testing.T, buf *bytes.Buffer) []AuditLogEntry {
	t.Helper()
	var entries []AuditLogEntry
	scanner := bufio.NewScanner(buf)
	for scanner.Scan() {
		line := scanner.Text()
		var entry AuditLogEntry
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			continue
		}
		if entry.Msg == "audit.event" {
			entries = append(entries, entry)
		}
	}
	return entries
}

func TestTC06482_SuccessfulLogin(t *testing.T) {
	r, buf, db := setupTC06482(t)
	defer db.Exec("DELETE FROM login_requests")

	body := []byte(`{"subject":"user-alice","remember":false,"remember_for":0}`)
	req, _ := http.NewRequest(http.MethodPut,
		"/admin/login/accept?login_challenge=challenge-accept-tc06482",
		bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "10.20.30.40:12345"

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code, "handler response: %s", w.Body.String())

	// Wait for the audit goroutine to flush to the buffer.
	time.Sleep(100 * time.Millisecond)

	events := parseAuditEvents(t, buf)
	require.NotEmpty(t, events, "expected at least one audit.event log line")

	e := events[0]
	// (a) event field is populated
	assert.NotEmpty(t, e.Event, "event field must be populated")
	assert.Equal(t, "auth.login.accept", e.Event)

	// (b) relying_party_url is populated
	assert.NotEmpty(t, e.RelyingPartyURL, "relying_party_url must be populated")

	// (c) client_ip is the forwarded address
	assert.Equal(t, "10.20.30.40", e.ClientIP, "client_ip must match X-Forwarded-For")

	// (d) user_identifier is populated
	assert.NotEmpty(t, e.UserIdentifier, "user_identifier must be populated")
	assert.Equal(t, "user-alice", e.UserIdentifier)
}

func TestTC06482_FailedLogin(t *testing.T) {
	r, buf, db := setupTC06482(t)
	defer db.Exec("DELETE FROM login_requests")

	body := []byte(`{"error":"access_denied","error_description":"Invalid credentials"}`)
	req, _ := http.NewRequest(http.MethodPut,
		"/admin/login/reject?login_challenge=challenge-reject-tc06482",
		bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "10.20.30.40:12345"

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code, "handler response: %s", w.Body.String())

	// Wait for the audit goroutine to flush to the buffer.
	time.Sleep(100 * time.Millisecond)

	events := parseAuditEvents(t, buf)
	require.NotEmpty(t, events, "expected at least one audit.event log line")

	e := events[0]
	// (a) event field is populated
	assert.NotEmpty(t, e.Event, "event field must be populated")
	assert.Equal(t, "auth.login.reject", e.Event)

	// (b) relying_party_url is populated
	assert.NotEmpty(t, e.RelyingPartyURL, "relying_party_url must be populated")

	// (c) client_ip is the forwarded address
	assert.Equal(t, "10.20.30.40", e.ClientIP, "client_ip must match X-Forwarded-For")

	// (d) user_identifier is populated (subject was pre-set on the login request)
	assert.NotEmpty(t, e.UserIdentifier, "user_identifier must be populated")
	assert.Equal(t, "user-bob", e.UserIdentifier)
}
