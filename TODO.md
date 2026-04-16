# Shyntr Feature Backlog

> Codebase snapshot: 13 domain model files · 14 GORM model files · 15 port files · 14 usecase files · 14 repository files  
> All checklist items use exact naming conventions from the repo.

---

## 1. LDAP Provider Integration

Allow tenants to federate identities via an LDAP/Active Directory directory.  
Pattern: mirror `connection_saml.go` / `SAMLConnectionUseCase` / `SAMLConnectionRepository` throughout.

### 1.1 Domain model — `internal/domain/model/`

- [ ] Create `connection_ldap.go` (14th model file) with `LDAPConnection` struct  
  Fields: `ID`, `TenantID`, `Name`, `ServerURL`, `BindDN`, `BindPassword` (never logged), `BaseDN`, `UserSearchFilter`, `UserSearchAttributes []string`, `GroupSearchFilter`, `GroupSearchBaseDN`, `AttributeMapping map[string]AttributeMappingRule`, `StartTLS bool`, `TLSInsecureSkipVerify bool`, `Active bool`, `CreatedAt`, `UpdatedAt`  
  Add `Validate() error` matching `SAMLConnection.Validate()` style  
  **Overlap:** reuse `AttributeMappingRule` already in `crypto_mapping.go`

### 1.2 Port — `internal/application/port/`

- [ ] Add `LDAPConnectionRepository` interface to `connection_repository.go` (alongside `OIDCConnectionRepository` and `SAMLConnectionRepository`):
  ```
  Create(ctx, conn *model.LDAPConnection) error
  GetByID(ctx, id string) (*model.LDAPConnection, error)
  GetByTenantAndID(ctx, tenantID, id string) (*model.LDAPConnection, error)
  GetConnectionCount(ctx, tenantID string) (int64, error)
  Update(ctx, conn *model.LDAPConnection) error
  Delete(ctx, tenantID, id string) error
  ListByTenant(ctx, tenantID string) ([]*model.LDAPConnection, error)
  ListActiveByTenant(ctx, tenantID string) ([]*model.LDAPConnection, error)
  List(ctx) ([]*model.LDAPConnection, error)
  ```
- [ ] Create `ldap_port.go` with `LDAPDialer` interface:
  ```
  Dial(ctx context.Context, conn *model.LDAPConnection) (LDAPSession, error)
  ```
  and `LDAPSession` interface:
  ```
  Authenticate(ctx context.Context, userDN, password string) error
  Search(ctx context.Context, filter string, attrs []string) ([]LDAPEntry, error)
  Close() error
  ```

### 1.3 Persistence — `internal/adapters/persistence/`

- [ ] Create `internal/adapters/persistence/models/connection_ldap_gorm.go` (15th GORM model file)  
  Struct `LDAPConnectionGORM` with GORM tags; `TableName() string` returns `"ldap_connections"`  
  `BeforeCreate` sets `ID = uuid.New().String()` if empty  
  `BindPassword` stored encrypted (AES-256-GCM via `AppSecret`, same pattern as `CryptoKeyGORM.KeyData`)  
  `AttributeMapping` serialized with `gorm:"serializer:json"`  
  Implement `ToDomain() *model.LDAPConnection` and `FromDomainLDAPConnection(e *model.LDAPConnection) *LDAPConnectionGORM`

- [ ] Create `internal/adapters/persistence/repository/connection_ldap_repository.go` (15th repository file)  
  Unexported struct `ldapConnectionRepository` with `*gorm.DB`; constructor `NewLDAPConnectionRepository(db *gorm.DB) port.LDAPConnectionRepository`  
  Implement all nine interface methods; all `ListByTenant` / `GetByTenantAndID` calls scope by `tenant_id`

- [ ] Add `&models.LDAPConnectionGORM{}` to the `AutoMigrate` call in `internal/adapters/persistence/database.go`

### 1.4 LDAP dialer adapter — `internal/adapters/ldap/`

- [ ] Create `internal/adapters/ldap/ldap_dialer.go`  
  Struct `ldapDialer`; constructor `NewLDAPDialer() port.LDAPDialer`  
  Use `github.com/go-ldap/ldap/v3`; honour `StartTLS` and `TLSInsecureSkipVerify` from `LDAPConnection`  
  Never log `BindPassword` or user passwords

### 1.5 Use case — `internal/application/usecase/`

- [ ] Create `connection_ldap_usecase.go` (15th usecase file)  
  Interface `LDAPConnectionUseCase`:
  ```
  CreateConnection(ctx, tenantID, actor, ip, ua string, conn *model.LDAPConnection) error
  GetConnection(ctx, tenantID, id string) (*model.LDAPConnection, error)
  GetConnectionCount(ctx, tenantID string) (int64, error)
  TestConnection(ctx, tenantID, id string) error
  UpdateConnection(ctx, tenantID, actor, ip, ua string, conn *model.LDAPConnection) error
  DeleteConnection(ctx, tenantID, actor, ip, ua, id string) error
  ListConnections(ctx, tenantID string) ([]*model.LDAPConnection, error)
  AuthenticateUser(ctx, tenantID, id, username, password string) (*model.LDAPEntry, error)
  ```
  Unexported struct `ldapConnectionUseCase`; constructor `NewLDAPConnectionUseCase(repo port.LDAPConnectionRepository, dialer port.LDAPDialer, audit port.AuditLogger, scope ScopeUseCase, outbound port.OutboundGuard) LDAPConnectionUseCase`  
  `CreateConnection` validates URL via `outbound.ValidateURL(ctx, tenantID, model.OutboundTargetType("ldap_auth"), serverURL)` — add `ldap_auth` to `OutboundTargetType` enum in `outbound_policy.go`  
  Audit actions: `"management.ldap_connection.create"`, `"management.ldap_connection.update"`, `"management.ldap_connection.delete"`

### 1.6 HTTP layer — `internal/adapters/http/`

- [ ] Add LDAP connection DTO structs to `internal/adapters/http/payload/connection_dto.go` (alongside existing OIDC/SAML DTOs):
  `CreateLDAPConnectionRequest`, `UpdateLDAPConnectionRequest`, `LDAPConnectionResponse`

- [ ] Add LDAP connection handler methods to `internal/adapters/http/handlers/management.go`:
  `CreateLDAPConnection`, `GetLDAPConnection`, `UpdateLDAPConnection`, `DeleteLDAPConnection`, `ListLDAPConnections`, `TestLDAPConnection`

- [ ] Wire routes in `internal/adapters/http/router.go` under the existing `/admin/management/` group:
  ```
  POST   /ldap-connections
  GET    /ldap-connections
  GET    /ldap-connections/:connection_id
  PUT    /ldap-connections/:connection_id
  DELETE /ldap-connections/:connection_id
  POST   /ldap-connections/:connection_id/test
  ```

### 1.7 CLI — `cmd/server/main.go`

- [ ] Add Cobra sub-commands: `create-ldap-connection`, `get-ldap-connection`, `delete-ldap-connection` (mirror `create-saml-connection` block)

### 1.8 Wiring — `cmd/server/main.go` `runServer`

- [ ] Instantiate `NewLDAPConnectionRepository(db)`, `NewLDAPDialer()`, `NewLDAPConnectionUseCase(...)`
- [ ] Pass `ldapConnectionUseCase` to `router.SetupRouter()` (add parameter after `samlConnectionUseCase`)

---

## 2. OAuth DPoP (RFC 9449)

Bind access tokens to a client-held key-pair; prevent token replay without possession proof.

### 2.1 Existing code to extend (do NOT create from scratch)

- `internal/domain/model/crypto_mapping.go` — `BlacklistedJTI` struct and `ValidateCipherSuite()` / `ValidateIncomingJWEHeader()` helpers are directly reusable for DPoP `jti` deduplication and `ath` / `htu` / `htm` header validation.
- `internal/application/port/crypto_mapping_repository.go` — `BlacklistedJTIRepository` (`Save`, `Exists`) already provides the replay-prevention store DPoP requires; reuse without modification.
- `internal/adapters/persistence/models/crypto_mapping_gorm.go` — `BlacklistedJTIGORM` GORM model already migrated; no new table needed for DPoP JTI deduplication.
- `internal/adapters/persistence/repository/crypto_mapping_repository.go` — `blacklistedJTIRepository` implementation already handles the `Save`/`Exists` contract.
- `internal/adapters/iam/fosite_store.go` — `SetClientAssertionJWT` / `ClientAssertionJWTValid` / `IsJWTUsed` / `MarkJWTUsedForTime` already exercise the JTI blacklist path; DPoP proof `jti` must be funnelled through the same store methods.
- `internal/adapters/iam/jwe_strategy.go` — JWE encryption helpers reusable for DPoP-bound encrypted tokens.

### 2.2 Domain model — `internal/domain/model/`

- [ ] Add `DPoPProof` struct to `crypto_mapping.go` (no new file; keep crypto concerns co-located):
  ```go
  type DPoPProof struct {
      JTI    string
      HTM    string    // HTTP method
      HTU    string    // HTTP URI
      IAT    time.Time
      ATH    string    // base64url(SHA-256(access_token)) — only on resource requests
      Nonce  string    // server-issued nonce (optional per RFC 9449 §8)
  }
  ```
- [ ] Add `DPoPNonce` struct to `crypto_mapping.go`:
  ```go
  type DPoPNonce struct {
      Value     string
      TenantID  string
      ExpiresAt time.Time
      CreatedAt time.Time
  }
  ```

### 2.3 Port — `internal/application/port/`

- [ ] Create `dpop_port.go` with `DPoPValidator` interface:
  ```
  ValidateProof(ctx context.Context, proof *model.DPoPProof, accessToken string, tenantID string) error
  IssueNonce(ctx context.Context, tenantID string) (string, error)
  ValidateNonce(ctx context.Context, nonce, tenantID string) error
  ```
- [ ] Add `DPoPNonceRepository` interface to `crypto_mapping_repository.go` (alongside `CryptoKeyRepository` and `BlacklistedJTIRepository`):
  ```
  SaveNonce(ctx context.Context, nonce *model.DPoPNonce) error
  GetNonce(ctx context.Context, value, tenantID string) (*model.DPoPNonce, error)
  DeleteExpiredNonces(ctx context.Context) error
  ```

### 2.4 Persistence — `internal/adapters/persistence/`

- [ ] Add `DPoPNonceGORM` struct to `internal/adapters/persistence/models/crypto_mapping_gorm.go` (extend existing file, do not create a new one):
  `TableName()` → `"dpop_nonces"`; `BeforeCreate` sets `Value = hex.EncodeToString(rand[32])` if empty; `TenantID` indexed
- [ ] Add `DPoPNonceGORM{}` to `AutoMigrate` in `database.go`
- [ ] Add `SaveNonce`, `GetNonce`, `DeleteExpiredNonces` methods to `internal/adapters/persistence/repository/crypto_mapping_repository.go` (extend existing file)

### 2.5 DPoP validator adapter — `internal/adapters/iam/`

- [ ] Create `internal/adapters/iam/dpop_validator.go`  
  Struct `dpopValidator`; constructor `NewDPoPValidator(jtiRepo port.BlacklistedJTIRepository, nonceRepo port.DPoPNonceRepository, km utils2.KeyManager) port.DPoPValidator`  
  `ValidateProof`: parse detached JWS, verify `jwk` header thumbprint ownership, check `htm`/`htu`, verify `iat` within ±30 s, verify `ath` when present, call `jtiRepo.Exists` then `jtiRepo.Save` for replay prevention  
  Never log the raw DPoP proof header

### 2.6 Use case — `internal/application/usecase/`

- [ ] Extend `internal/application/usecase/client_oidc_usecase.go`:  
  Add `ValidateDPoPProof(ctx context.Context, tenantID, clientID, rawProof, accessToken string) error` to `OAuth2ClientUseCase` interface and implementation  
  Constructor already receives `KeyManager` — pass `DPoPValidator` as an additional dependency

### 2.7 Token endpoint — `internal/adapters/iam/` and `internal/adapters/http/handlers/`

- [ ] Extend `internal/adapters/iam/fosite_store.go`: implement `fosite.DPoPStorage` interface (`GetDPoPJKT`, `SetDPoPJKT`)
- [ ] Extend `internal/adapters/http/handlers/oauth2.go` token handler:  
  Extract `DPoP` header, call `dpopValidator.ValidateProof`; on first use, issue nonce via `DPoP-Nonce` response header; enforce binding in introspection response  
  Return `use_dpop_nonce` error per RFC 9449 §7 when nonce stale

### 2.8 OAuth2Session binding

- [ ] Add `DPoPJKT string` (JWK Thumbprint) to `internal/domain/model/oauth2_session.go` `OAuth2Session` struct
- [ ] Add `dpop_jkt varchar` column to `OAuth2SessionGORM` in `internal/adapters/persistence/models/oauth2_session_gorm.go`; add to `AutoMigrate`

### 2.9 Wiring — `cmd/server/main.go` `runServer`

- [ ] Instantiate `NewDPoPValidator(jtiRepo, nonceRepo, km)`
- [ ] Pass to `NewOAuth2ClientUseCase(...)` (add parameter)

---

## 3. OAuth SPIFFE Client Authentication

Allow workloads presenting a SPIFFE SVID to authenticate as OAuth2 confidential clients without a static secret.

### 3.1 Existing code to extend (do NOT create from scratch)

- `internal/domain/model/client_oidc.go` — `OAuth2Client.TokenEndpointAuthMethod` already accepts string values (`private_key_jwt`, `client_secret_basic`, etc.); add `"tls_client_auth"` / `"self_signed_tls_client_auth"` without changing the field type.
- `internal/application/port/crypto_mapping_repository.go` — `BlacklistedJTIRepository` reusable for SVID-bound proof replay prevention.
- `internal/adapters/iam/fosite_store.go` — client auth method dispatch is centralised here; extend `GetClient` path or implement `fosite.ClientAuthenticationStrategy`.
- `internal/adapters/iam/fosite_client.go` — `FositeClient` wrapper for `OAuth2Client`; add SPIFFE trust domain and allowed SVID patterns there.
- `internal/adapters/http/middleware/security.go` — TLS client certificate extraction goes here (add `ExtractClientCert` middleware that populates `gin.Context`).

### 3.2 Domain model — `internal/domain/model/`

- [ ] Add SPIFFE fields to `client_oidc.go` `OAuth2Client` struct (no new file):
  ```go
  SPIFFETrustDomain    string   // e.g. "spiffe://prod.example.com"
  AllowedSPIFFEIDs     []string // exact SVID URIs allowed to authenticate as this client
  SVIDRotationGraceSec int      // accept certs expiring within this window (default 30)
  ```
- [ ] Create `internal/domain/model/spiffe_trust.go` (14th domain model file) with `SPIFFETrustBundle` struct:
  ```go
  type SPIFFETrustBundle struct {
      ID          string
      TenantID    string
      TrustDomain string
      BundlePEM   []byte  // X.509 bundle PEM, never logged
      RefreshedAt time.Time
      ExpiresAt   time.Time
      CreatedAt   time.Time
      UpdatedAt   time.Time
  }
  ```

### 3.3 Port — `internal/application/port/`

- [ ] Create `spiffe_port.go` with `SPIFFEVerifier` interface:
  ```
  VerifySVID(ctx context.Context, rawCert *x509.Certificate, tenantID, clientID string) (spiffeID string, err error)
  FetchBundle(ctx context.Context, trustDomain, bundleEndpoint string) (*model.SPIFFETrustBundle, error)
  ```
- [ ] Add `SPIFFETrustBundleRepository` interface to `connection_repository.go` (alongside OIDC/SAML/LDAP connection repositories):
  ```
  Create(ctx, bundle *model.SPIFFETrustBundle) error
  GetByTenantAndDomain(ctx, tenantID, trustDomain string) (*model.SPIFFETrustBundle, error)
  Upsert(ctx, bundle *model.SPIFFETrustBundle) error
  Delete(ctx, tenantID, id string) error
  ListByTenant(ctx, tenantID string) ([]*model.SPIFFETrustBundle, error)
  ```

### 3.4 Persistence — `internal/adapters/persistence/`

- [ ] Create `internal/adapters/persistence/models/spiffe_trust_gorm.go` (16th GORM model file)  
  Struct `SPIFFETrustBundleGORM`; `TableName()` → `"spiffe_trust_bundles"`  
  `BundlePEM` stored with `gorm:"type:bytea"` (same as `CryptoKeyGORM.KeyData`)  
  `BeforeCreate` sets `ID = uuid.New().String()`  
  `(TenantID, TrustDomain)` unique index

- [ ] Create `internal/adapters/persistence/repository/spiffe_trust_repository.go` (16th repository file)  
  Unexported struct `spiffeTrustBundleRepository`; constructor `NewSPIFFETrustBundleRepository(db *gorm.DB) port.SPIFFETrustBundleRepository`

- [ ] Add `OAuth2Client` SPIFFE columns migration: add `spiffe_trust_domain varchar`, `allowed_spiffe_ids text[]`, `svid_rotation_grace_sec int` to `client_oidc_gorm.go` `OAuth2ClientGORM` and `AutoMigrate`

- [ ] Add `&models.SPIFFETrustBundleGORM{}` to `AutoMigrate` in `database.go`

### 3.5 SPIFFE verifier adapter — `internal/adapters/iam/`

- [ ] Create `internal/adapters/iam/spiffe_verifier.go`  
  Struct `spiffeVerifier`; constructor `NewSPIFFEVerifier(bundleRepo port.SPIFFETrustBundleRepository, guard port.OutboundGuard) port.SPIFFEVerifier`  
  `VerifySVID`: build x509 verification pool from stored `SPIFFETrustBundle.BundlePEM`, verify cert chain, extract SPIFFE URI SAN, match against `OAuth2Client.AllowedSPIFFEIDs`, enforce `SVIDRotationGraceSec`  
  `FetchBundle`: call `guard.ValidateURL(ctx, tenantID, "spiffe_bundle_fetch", endpoint)` before HTTP fetch; parse SPIFFE bundle endpoint response (RFC 8555-style JSON)  
  Never log raw SVID or bundle PEM

### 3.6 Use case — `internal/application/usecase/`

- [ ] Extend `internal/application/usecase/client_oidc_usecase.go`:  
  Add `RegisterSPIFFETrustDomain(ctx, tenantID, actor, ip, ua, clientID, trustDomain, bundleEndpoint string) error` and `RotateSPIFFEBundle(ctx, tenantID, clientID string) error` to `OAuth2ClientUseCase` interface and implementation  
  Pass `SPIFFEVerifier` as additional constructor dependency

- [ ] Create `internal/application/usecase/spiffe_trust_usecase.go` (15th usecase file) with `SPIFFETrustUseCase` interface:
  ```
  CreateBundle(ctx, tenantID, actor, ip, ua string, bundle *model.SPIFFETrustBundle) error
  GetBundle(ctx, tenantID, id string) (*model.SPIFFETrustBundle, error)
  RefreshBundle(ctx, tenantID, id string) error
  DeleteBundle(ctx, tenantID, actor, ip, ua, id string) error
  ListBundles(ctx, tenantID string) ([]*model.SPIFFETrustBundle, error)
  ```
  Constructor: `NewSPIFFETrustUseCase(repo port.SPIFFETrustBundleRepository, verifier port.SPIFFEVerifier, audit port.AuditLogger, outbound port.OutboundGuard) SPIFFETrustUseCase`  
  Audit actions: `"management.spiffe_bundle.create"`, `"management.spiffe_bundle.refresh"`, `"management.spiffe_bundle.delete"`

### 3.7 Token endpoint — `internal/adapters/iam/` and `internal/adapters/http/`

- [ ] Extend `internal/adapters/http/middleware/security.go`: add `TLSClientCertMiddleware()` that extracts verified peer certificate from `tls.ConnectionState` and stores in `gin.Context` under key `"tls_client_cert"`
- [ ] Extend `internal/adapters/iam/fosite_store.go`: implement SPIFFE branch in client authentication strategy — when `TokenEndpointAuthMethod == "tls_client_auth"` or `"self_signed_tls_client_auth"`, call `spiffeVerifier.VerifySVID` instead of secret comparison
- [ ] Enable mutual TLS on the public listener in `cmd/server/main.go` `runServer` (make optional via `cfg.MTLS.Enabled` flag)

### 3.8 HTTP layer — `internal/adapters/http/`

- [ ] Add `SPIFFETrustBundle` DTO structs to `internal/adapters/http/payload/connection_dto.go`:  
  `CreateSPIFFEBundleRequest`, `SPIFFEBundleResponse`

- [ ] Add handler methods to `internal/adapters/http/handlers/management.go`:  
  `CreateSPIFFEBundle`, `GetSPIFFEBundle`, `DeleteSPIFFEBundle`, `RefreshSPIFFEBundle`, `ListSPIFFEBundles`

- [ ] Wire routes in `router.go` under `/admin/management/`:
  ```
  POST   /spiffe-bundles
  GET    /spiffe-bundles
  GET    /spiffe-bundles/:bundle_id
  DELETE /spiffe-bundles/:bundle_id
  POST   /spiffe-bundles/:bundle_id/refresh
  ```

### 3.9 Wiring — `cmd/server/main.go` `runServer`

- [ ] Instantiate `NewSPIFFETrustBundleRepository(db)`, `NewSPIFFEVerifier(bundleRepo, outboundGuard)`, `NewSPIFFETrustUseCase(...)`
- [ ] Pass `spiffeTrustUseCase` and `spiffeVerifier` to `router.SetupRouter()` and `NewOAuth2ClientUseCase(...)` respectively

---

## Cross-cutting

- [ ] `internal/adapters/persistence/database.go` — single `AutoMigrate` call must include all new GORM structs: `LDAPConnectionGORM`, `DPoPNonceGORM`, `SPIFFETrustBundleGORM` and the new columns on `OAuth2ClientGORM`
- [ ] `internal/domain/model/outbound_policy.go` — add `"ldap_auth"` and `"spiffe_bundle_fetch"` to `OutboundTargetType` enum
- [ ] `internal/adapters/http/router.go` `SetupRouter` — add `ldapConnectionUseCase LDAPConnectionUseCase`, `spiffeTrustUseCase SPIFFETrustUseCase` parameters (after existing connection use-case params)
- [ ] All new `BindPassword` / `BundlePEM` / SVID fields must follow the existing `"never log secrets"` rule from `CLAUDE.md`; audit `details` maps must omit these fields
- [ ] Each new production-path change must have a companion integration test (real HTTP boundary, no mocked DB) per `CLAUDE.md` testing rule
