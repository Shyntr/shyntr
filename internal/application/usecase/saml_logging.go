package usecase

import (
	"context"
	"crypto/sha256"
	"encoding/hex"

	"github.com/Shyntr/shyntr/pkg/logger"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
)

// samlCorrelationKey types the correlation values threaded from the HTTP layer
// into use-case SAML logging. A private key type avoids collisions with any
// other value stored in the same context.
type samlCorrelationKey int

const (
	ctxKeyLoginChallenge samlCorrelationKey = iota
	ctxKeyTraceID
)

// WithSAMLCorrelation returns a context carrying the flow-spanning
// login_challenge and the request trace_id so every use-case SAML log line can
// be correlated across InitiateSSO, HandleACS, and issuance. Empty values are
// not stored. The full login_challenge is carried here but only ever emitted as
// a bounded prefix (see samlFlowLogger); it is a Shyntr-internal handle, never a
// user value.
func WithSAMLCorrelation(ctx context.Context, loginChallenge, traceID string) context.Context {
	if loginChallenge != "" {
		ctx = context.WithValue(ctx, ctxKeyLoginChallenge, loginChallenge)
	}
	if traceID != "" {
		ctx = context.WithValue(ctx, ctxKeyTraceID, traceID)
	}
	return ctx
}

func loginChallengeFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(ctxKeyLoginChallenge).(string); ok {
		return v
	}
	return ""
}

func traceIDFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(ctxKeyTraceID).(string); ok && v != "" {
		return v
	}
	// Fall back to an OpenTelemetry span carried in ctx, matching logger.FromGin.
	if span := trace.SpanFromContext(ctx); span.SpanContext().HasTraceID() {
		return span.SpanContext().TraceID().String()
	}
	return ""
}

// samlFlowLogger builds the base logger for use-case SAML logs. It attaches the
// login_challenge prefix (never the full value) and the trace_id when present,
// so an operator can follow one federation flow end to end across use-case and
// handler log lines.
//
// SAFE-FIELDS INVARIANT: lines built from this logger must carry only message
// type, binding, partner entity ID, tenant ID, signature status, NameID FORMAT,
// attribute NAMES, outcome/category, and hashed/prefixed identifiers — never a
// raw subject, NameID value, assertion, claim value, token, or key material.
func samlFlowLogger(ctx context.Context) *zap.Logger {
	log := logger.Log
	if log == nil {
		return zap.NewNop()
	}
	log = log.With(zap.String("protocol", "saml"))
	if lc := loginChallengeFromContext(ctx); lc != "" {
		log = log.With(zap.String("login_challenge_prefix", logShortID(lc, 12)))
	}
	if tid := traceIDFromContext(ctx); tid != "" {
		log = log.With(zap.String("trace_id", tid))
	}
	return log
}

// logWireMessageBody logs a raw on-the-wire SAML message body at Debug, gated by
// SAML_DEBUG_LOG_MESSAGE_BODIES (default false; nil-Config safe). The caller MUST
// pass the wire form — the bytes as received or sent, BEFORE any decryption — so
// the body may carry the (public) signature and certificate and an
// EncryptedAssertion as ciphertext, but never decrypted plaintext, a private key,
// or a secret. Every emitted line is marked UNSAFE_DEBUG and correlated like the
// structured flow logs.
func (s *samlBuilderUseCase) logWireMessageBody(ctx context.Context, messageType string, wireBody []byte) {
	if s.Config == nil || !s.Config.SAMLDebugLogMessageBodies {
		return
	}
	samlFlowLogger(ctx).Debug("SAML raw message body (debug)",
		zap.String("event", "saml.debug.message_body"),
		zap.String("message_type", messageType),
		zap.String("UNSAFE_DEBUG", "raw message body logged; disable in production"),
		zap.String("message_body", string(wireBody)),
	)
}

// logShortID returns a bounded prefix of an identifier for correlation logging.
// It mirrors the handler-side shortForLog: a prefix, never the full value.
func logShortID(value string, max int) string {
	if value == "" || max <= 0 {
		return ""
	}
	if len(value) <= max {
		return value
	}
	return value[:max]
}

// logHashID returns the SHA-256 hex digest of an identifier, mirroring the
// handler-side hashForLog. It lets an identifier (e.g. an assertion ID) be
// correlated across log lines without ever being emitted in the clear.
func logHashID(value string) string {
	if value == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}
