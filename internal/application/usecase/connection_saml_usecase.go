package usecase

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"

	"github.com/Shyntr/shyntr/pkg/logger"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/Shyntr/shyntr/internal/application/port"
	shyntrsaml "github.com/Shyntr/shyntr/internal/application/utils"
	"github.com/Shyntr/shyntr/internal/domain/model"
	"github.com/crewjam/saml"
)

type SAMLConnectionUseCase interface {
	CreateConnection(ctx context.Context, conn *model.SAMLConnection, actorIP, userAgent string) (*model.SAMLConnection, error)
	GetConnection(ctx context.Context, tenantID, id string) (*model.SAMLConnection, error)
	GetConnectionCount(ctx context.Context, tenantID string) (int64, error)
	GetConnectionByIdpEntity(ctx context.Context, tenantID, idpEntity string) (*model.SAMLConnection, error)
	UpdateConnection(ctx context.Context, conn *model.SAMLConnection, actorIP, userAgent string) error
	DeleteConnection(ctx context.Context, tenantID, id string, actorIP, userAgent string) error
	ListConnectionsByTenant(ctx context.Context, tenantID string) ([]*model.SAMLConnection, error)
	ListAllConnections(ctx context.Context) ([]*model.SAMLConnection, error)
	bindMappingScopes(ctx context.Context, tenantID string, mappings map[string]model.AttributeMappingRule)
}

type samlConnectionUseCase struct {
	repo     port.SAMLConnectionRepository
	audit    port.AuditLogger
	scopeUse ScopeUseCase
	outbound port.OutboundGuard
}

func NewSAMLConnectionUseCase(repo port.SAMLConnectionRepository, audit port.AuditLogger, scopeUse ScopeUseCase, outbound port.OutboundGuard) SAMLConnectionUseCase {
	return &samlConnectionUseCase{
		repo:     repo,
		audit:    audit,
		scopeUse: scopeUse,
		outbound: outbound,
	}
}

func (u *samlConnectionUseCase) bindMappingScopes(ctx context.Context, tenantID string, mappings map[string]model.AttributeMappingRule) {
	for _, rule := range mappings {
		if len(rule.TargetScopes) > 0 && rule.Target != "" {
			err := u.scopeUse.AddClaimToScopes(ctx, tenantID, rule.Target, rule.TargetScopes)
			if err != nil {
				logger.Log.Warn("Failed to auto-bind claim to scopes during connection save",
					zap.String("tenant_id", tenantID),
					zap.String("claim", rule.Target),
					zap.Error(err),
				)
			}
		}
	}
}

func (u *samlConnectionUseCase) CreateConnection(ctx context.Context, conn *model.SAMLConnection, actorIP, userAgent string) (*model.SAMLConnection, error) {
	if conn.ID == "" {
		conn.ID = uuid.New().String()
	}

	var descriptor *saml.EntityDescriptor
	if conn.MetadataURL != "" {
		meta, rawXML, err := shyntrsaml.FetchAndParseMetadata(ctx, conn.TenantID, conn.MetadataURL, u.outbound)
		if err != nil {
			return nil, err
		}
		if conn.IdpMetadataXML == "" {
			conn.IdpMetadataXML = rawXML
		}
		descriptor = meta
	} else if conn.IdpMetadataXML != "" {
		meta := &saml.EntityDescriptor{}
		if err := xml.Unmarshal([]byte(conn.IdpMetadataXML), meta); err != nil {
			return nil, errors.New("Invalid SAML IdP metadata XML")
		}
		descriptor = meta
		conn.IdpEntityID = meta.EntityID
	} else {
		if conn.IdpEntityID == "" || conn.IdpSingleSignOn == "" {
			return nil, errors.New("idp_entity_id and idp_sso_url are required if metadata_url is not provided")
		}
	}

	if descriptor != nil {
		if conn.IdpEntityID == "" {
			conn.IdpEntityID = descriptor.EntityID
		}
		if len(descriptor.IDPSSODescriptors) > 0 {
			idpDesc := descriptor.IDPSSODescriptors[0]
			if conn.IdpSingleSignOn == "" {
				for _, sso := range idpDesc.SingleSignOnServices {
					conn.IdpSingleSignOn = sso.Location
					if sso.Binding == saml.HTTPRedirectBinding {
						break
					}
				}
			}
			if conn.IdpSloUrl == "" {
				for _, slo := range idpDesc.SingleLogoutServices {
					conn.IdpSloUrl = slo.Location
					if slo.Binding == saml.HTTPRedirectBinding {
						break
					}
				}
			}
			for _, kd := range idpDesc.KeyDescriptors {
				if len(kd.KeyInfo.X509Data.X509Certificates) > 0 {
					certData := shyntrsaml.FormatCertificate(kd.KeyInfo.X509Data.X509Certificates[0].Data)
					if kd.Use == "signing" || kd.Use == "" {
						if conn.IdpCertificate == "" {
							conn.IdpCertificate = certData
						}
					}
					if kd.Use == "encryption" || kd.Use == "" {
						if conn.IdpEncryptionCertificate == "" {
							conn.IdpEncryptionCertificate = certData
						}
					}
				}
			}
		}
	}

	conn.Active = true

	if err := conn.Validate(); err != nil {
		return nil, err
	}

	if err := u.repo.Create(ctx, conn); err != nil {
		return nil, err
	}

	u.bindMappingScopes(ctx, conn.TenantID, conn.AttributeMapping)
	u.audit.Log(conn.TenantID, "system", "management.connection.saml.create", actorIP, userAgent, map[string]interface{}{
		"connection_id": conn.ID,
		"entity_id":     conn.IdpEntityID,
		"metadata_url":  conn.MetadataURL,
	})

	return conn, nil
}

func (u *samlConnectionUseCase) GetConnection(ctx context.Context, tenantID, id string) (*model.SAMLConnection, error) {
	return u.repo.GetByTenantAndID(ctx, tenantID, id)
}

func (u *samlConnectionUseCase) GetConnectionCount(ctx context.Context, tenantID string) (int64, error) {
	return u.repo.GetConnectionCount(ctx, tenantID)
}

func (u *samlConnectionUseCase) GetConnectionByIdpEntity(ctx context.Context, tenantID, idpEntity string) (*model.SAMLConnection, error) {
	return u.repo.GetConnectionByIdpEntity(ctx, tenantID, idpEntity)
}

func (u *samlConnectionUseCase) UpdateConnection(ctx context.Context, conn *model.SAMLConnection, actorIP, userAgent string) error {
	var descriptor *saml.EntityDescriptor
	if conn.MetadataURL != "" {
		meta, rawXML, err := shyntrsaml.FetchAndParseMetadata(ctx, conn.TenantID, conn.MetadataURL, u.outbound)
		if err != nil {
			return err
		}

		if conn.IdpMetadataXML == "" {
			conn.IdpMetadataXML = rawXML
		}
		descriptor = meta
	} else if conn.IdpMetadataXML != "" {
		meta := &saml.EntityDescriptor{}
		if err := xml.Unmarshal([]byte(conn.IdpMetadataXML), meta); err != nil {
			return errors.New("Invalid SAML IdP metadata XML")
		}
		descriptor = meta
		conn.IdpEntityID = meta.EntityID
	} else {
		if conn.IdpEntityID == "" || conn.IdpSingleSignOn == "" {
			return errors.New("idp_entity_id and idp_sso_url are required if metadata_url is not provided")
		}
	}

	if descriptor != nil {
		if conn.IdpEntityID == "" {
			conn.IdpEntityID = descriptor.EntityID
		}
		if len(descriptor.IDPSSODescriptors) > 0 {
			idpDesc := descriptor.IDPSSODescriptors[0]

			if conn.IdpSingleSignOn == "" {
				for _, sso := range idpDesc.SingleSignOnServices {
					conn.IdpSingleSignOn = sso.Location
					if sso.Binding == saml.HTTPRedirectBinding {
						break
					}
				}
			}

			if conn.IdpSloUrl == "" {
				for _, slo := range idpDesc.SingleLogoutServices {
					conn.IdpSloUrl = slo.Location
					if slo.Binding == saml.HTTPRedirectBinding {
						break
					}
				}
			}

			for _, kd := range idpDesc.KeyDescriptors {
				if len(kd.KeyInfo.X509Data.X509Certificates) > 0 {
					certData := shyntrsaml.FormatCertificate(kd.KeyInfo.X509Data.X509Certificates[0].Data)
					if kd.Use == "signing" || kd.Use == "" {
						if conn.IdpCertificate == "" {
							conn.IdpCertificate = certData
						}
					}

					if kd.Use == "encryption" || kd.Use == "" {
						if conn.IdpEncryptionCertificate == "" {
							conn.IdpEncryptionCertificate = certData
						}
					}
				}
			}
		}
	}
	conn.Active = true

	if err := conn.Validate(); err != nil {
		return err
	}
	if err := u.repo.Update(ctx, conn); err != nil {
		return err
	}
	u.bindMappingScopes(ctx, conn.TenantID, conn.AttributeMapping)

	u.audit.Log(conn.TenantID, "system", "management.connection.saml.update", actorIP, userAgent, map[string]interface{}{
		"connection_id": conn.ID,
		"entity_id":     conn.IdpEntityID,
		"metadata_url":  conn.MetadataURL,
	})

	return nil
}

func (u *samlConnectionUseCase) DeleteConnection(ctx context.Context, tenantID, id string, actorIP, userAgent string) error {
	if err := u.repo.Delete(ctx, tenantID, id); err != nil {
		return err
	}

	u.audit.Log(tenantID, "system", "management.connection.saml.delete", actorIP, userAgent, map[string]interface{}{
		"connection_id": id,
	})

	return nil
}

func (u *samlConnectionUseCase) ListConnectionsByTenant(ctx context.Context, tenantID string) ([]*model.SAMLConnection, error) {
	if tenantID == "" {
		return nil, fmt.Errorf("tenant_id is required")
	}
	return u.repo.ListByTenant(ctx, tenantID)
}

func (u *samlConnectionUseCase) ListAllConnections(ctx context.Context) ([]*model.SAMLConnection, error) {
	return u.repo.List(ctx)
}
