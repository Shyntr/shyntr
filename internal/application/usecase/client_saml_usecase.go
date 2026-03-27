package usecase

import (
	"context"
	"errors"

	"github.com/Shyntr/shyntr/internal/adapters/http/payload"
	"github.com/Shyntr/shyntr/internal/application/port"
	shyntrsaml "github.com/Shyntr/shyntr/internal/application/utils"
	"github.com/Shyntr/shyntr/internal/domain/model"
	"github.com/Shyntr/shyntr/pkg/utils"
	"github.com/crewjam/saml"
)

type SAMLClientUseCase interface {
	CreateClient(ctx context.Context, client *model.SAMLClient, actorIP, userAgent string) (*model.SAMLClient, error)
	GetClient(ctx context.Context, tenantID, id string) (*model.SAMLClient, error)
	GetClientCount(ctx context.Context, tenantID string) (int64, error)
	GetClientByEntityID(ctx context.Context, tenantID, entityID string) (*model.SAMLClient, error)
	UpdateClient(ctx context.Context, client *model.SAMLClient, actorIP, userAgent string) error
	DeleteClient(ctx context.Context, tenantID, id string, actorIP, userAgent string) error
	ListClients(ctx context.Context, tenantID string) ([]*payload.SAMLClientResponse, error)
}

type samlClientUseCase struct {
	repo   port.SAMLClientRepository
	tenant port.TenantRepository
	audit  port.AuditLogger
}

func NewSAMLClientUseCase(repo port.SAMLClientRepository, tenant port.TenantRepository, audit port.AuditLogger) SAMLClientUseCase {
	return &samlClientUseCase{repo: repo, tenant: tenant, audit: audit}
}

func (u *samlClientUseCase) CreateClient(ctx context.Context, client *model.SAMLClient, actorIP, userAgent string) (*model.SAMLClient, error) {
	if client.TenantID == "" {
		client.TenantID = "default"
	}
	if client.ID == "" {
		client.ID, _ = utils.GenerateRandomHex(8)
	}

	if client.MetadataURL != "" {
		descriptor, _, err := shyntrsaml.FetchAndParseMetadata(client.MetadataURL)
		if err != nil {
			return nil, errors.New("Invalid Metadata URL: " + err.Error())
		}
		if descriptor != nil {
			if client.EntityID == "" {
				client.EntityID = descriptor.EntityID
			}
			if len(descriptor.SPSSODescriptors) > 0 {
				sp := descriptor.SPSSODescriptors[0]
				if client.ACSURL == "" {
					for _, acs := range sp.AssertionConsumerServices {
						client.ACSURL = acs.Location
						if acs.Binding == saml.HTTPPostBinding {
							break
						}
					}
				}
				if client.SLOURL == "" {
					for _, slo := range sp.SingleLogoutServices {
						client.SLOURL = slo.Location
						if slo.Binding == saml.HTTPRedirectBinding {
							break
						}
					}
				}
				for _, kd := range sp.KeyDescriptors {
					if len(kd.KeyInfo.X509Data.X509Certificates) > 0 {
						certData := shyntrsaml.FormatCertificate(kd.KeyInfo.X509Data.X509Certificates[0].Data)
						if kd.Use == "signing" || kd.Use == "" {
							if client.SPCertificate == "" {
								client.SPCertificate = certData
							}
						}
						if kd.Use == "encryption" || kd.Use == "" {
							if client.SPEncryptionCertificate == "" {
								client.SPEncryptionCertificate = certData
							}
						}
					}
				}
			}
		}
	}
	if client.EntityID == "" || client.ACSURL == "" {
		return nil, errors.New("entity_id and acs_url are required if metadata_url is not provided")
	}

	client.SignResponse = true
	client.SignAssertion = true
	client.Active = true

	if err := client.Validate(); err != nil {
		return nil, err
	}

	if err := u.repo.Create(ctx, client); err != nil {
		return nil, err
	}

	u.audit.Log(client.TenantID, "system", "management.client.saml.create", actorIP, userAgent, map[string]interface{}{
		"client_id": client.ID,
		"entity_id": client.EntityID,
		"ip":        actorIP,
	})

	return client, nil
}

func (u *samlClientUseCase) GetClient(ctx context.Context, tenantID, id string) (*model.SAMLClient, error) {
	client, err := u.repo.GetByID(ctx, tenantID, id)
	if err != nil {
		return nil, err
	}
	return client, nil
}

func (u *samlClientUseCase) GetClientCount(ctx context.Context, tenantID string) (int64, error) {
	return u.repo.GetClientCount(ctx, tenantID)
}

func (u *samlClientUseCase) GetClientByEntityID(ctx context.Context, tenantID, entityID string) (*model.SAMLClient, error) {
	client, err := u.repo.GetByTenantAndEntityID(ctx, tenantID, entityID)
	if err != nil {
		return nil, err
	}
	return client, nil
}

func (u *samlClientUseCase) UpdateClient(ctx context.Context, client *model.SAMLClient, actorIP, userAgent string) error {
	if err := client.Validate(); err != nil {
		return err
	}
	if err := u.repo.Update(ctx, client); err != nil {
		return err
	}
	u.audit.Log(client.TenantID, "system", "management.client.saml.update", actorIP, userAgent, map[string]interface{}{
		"client_id": client.ID,
	})
	return nil
}

func (u *samlClientUseCase) DeleteClient(ctx context.Context, tenantID, id string, actorIP, userAgent string) error {
	if err := u.repo.Delete(ctx, tenantID, id); err != nil {
		return err
	}
	u.audit.Log(tenantID, "system", "management.client.saml.delete", actorIP, userAgent, map[string]interface{}{"client_id": id})
	return nil
}

func (u *samlClientUseCase) ListClients(ctx context.Context, tenantID string) ([]*payload.SAMLClientResponse, error) {
	clients, err := u.repo.ListByTenant(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	return payload.FromDomainSAMLClients(clients), nil
}
