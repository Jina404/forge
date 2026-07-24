package storage

import (
	"fmt"
	"sync"
	"time"

	"github.com/Jina404/forge/pkg/core"
	"github.com/Jina404/forge/pkg/evidence"
)

// InMemoryStore is a temporary persistence layer for campaign orchestration.
type InMemoryStore struct {
	mu              sync.RWMutex
	campaigns       map[string]core.Campaign
	campaignTenants map[string]string
	vulnerabilities map[string][]core.Vulnerability
	artifacts       map[string][]evidence.Artifact
	organizations   map[string]Organization
	users           map[string]User
	projects        map[string][]Project
	auditLogs       map[string][]AuditLog
}

func NewInMemoryStore() *InMemoryStore {
	return &InMemoryStore{
		campaigns:       make(map[string]core.Campaign),
		campaignTenants: make(map[string]string),
		vulnerabilities: make(map[string][]core.Vulnerability),
		artifacts:       make(map[string][]evidence.Artifact),
		organizations:   make(map[string]Organization),
		users:           make(map[string]User),
		projects:        make(map[string][]Project),
		auditLogs:       make(map[string][]AuditLog),
	}
}

func (s *InMemoryStore) SaveCampaign(campaign core.Campaign) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.campaigns[campaign.ID] = campaign
	return nil
}

func (s *InMemoryStore) GetCampaign(id string) (core.Campaign, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	campaign, ok := s.campaigns[id]
	if !ok {
		return core.Campaign{}, fmt.Errorf("campaign not found: %s", id)
	}
	return campaign, nil
}

func (s *InMemoryStore) SaveVulnerability(campaignID string, vulnerability core.Vulnerability) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.vulnerabilities[campaignID] = append(s.vulnerabilities[campaignID], vulnerability)
	return nil
}

func (s *InMemoryStore) ListVulnerabilities(campaignID string) ([]core.Vulnerability, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	items := s.vulnerabilities[campaignID]
	out := make([]core.Vulnerability, len(items))
	copy(out, items)
	return out, nil
}

func (s *InMemoryStore) SaveArtifact(campaignID string, artifact evidence.Artifact) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.artifacts[campaignID] = append(s.artifacts[campaignID], artifact)
	return nil
}

func (s *InMemoryStore) ListArtifacts(campaignID string) ([]evidence.Artifact, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	items := s.artifacts[campaignID]
	out := make([]evidence.Artifact, len(items))
	copy(out, items)
	return out, nil
}

func (s *InMemoryStore) SaveCampaignTenant(campaignID string, organizationID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.campaignTenants[campaignID] = organizationID
	return nil
}

func (s *InMemoryStore) GetCampaignTenant(campaignID string) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	orgID, ok := s.campaignTenants[campaignID]
	if !ok {
		return "", fmt.Errorf("campaign tenant not found: %s", campaignID)
	}
	return orgID, nil
}

func (s *InMemoryStore) CountOrganizations() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.organizations)
}

func (s *InMemoryStore) CreateOrganization(org Organization) (Organization, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if org.ID == "" {
		org.ID = fmt.Sprintf("org-%d", time.Now().UnixNano())
	}
	if org.CreatedAt.IsZero() {
		org.CreatedAt = time.Now().UTC()
	}
	s.organizations[org.ID] = org
	return org, nil
}

func (s *InMemoryStore) ListOrganizations() ([]Organization, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]Organization, 0, len(s.organizations))
	for _, org := range s.organizations {
		result = append(result, org)
	}
	return result, nil
}

func (s *InMemoryStore) GetOrganization(id string) (Organization, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	org, ok := s.organizations[id]
	if !ok {
		return Organization{}, fmt.Errorf("organization not found: %s", id)
	}
	return org, nil
}

func (s *InMemoryStore) CreateUser(user User) (User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, existing := range s.users {
		if existing.Email == user.Email {
			return User{}, fmt.Errorf("user already exists for email: %s", user.Email)
		}
	}
	if user.ID == "" {
		user.ID = fmt.Sprintf("usr-%d", time.Now().UnixNano())
	}
	if user.CreatedAt.IsZero() {
		user.CreatedAt = time.Now().UTC()
	}
	if !user.Active {
		user.Active = true
	}
	s.users[user.ID] = user
	return user, nil
}

func (s *InMemoryStore) GetUserByEmail(email string) (User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, user := range s.users {
		if user.Email == email {
			return user, nil
		}
	}
	return User{}, fmt.Errorf("user not found for email: %s", email)
}

func (s *InMemoryStore) ListUsersByOrganization(orgID string) ([]User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]User, 0)
	for _, user := range s.users {
		if user.OrganizationID == orgID {
			result = append(result, user)
		}
	}
	return result, nil
}

func (s *InMemoryStore) CreateProject(project Project) (Project, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if project.ID == "" {
		project.ID = fmt.Sprintf("prj-%d", time.Now().UnixNano())
	}
	if project.CreatedAt.IsZero() {
		project.CreatedAt = time.Now().UTC()
	}
	s.projects[project.OrganizationID] = append(s.projects[project.OrganizationID], project)
	return project, nil
}

func (s *InMemoryStore) ListProjectsByOrganization(orgID string) ([]Project, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	items := s.projects[orgID]
	out := make([]Project, len(items))
	copy(out, items)
	return out, nil
}

func (s *InMemoryStore) AppendAuditLog(log AuditLog) (AuditLog, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if log.ID == "" {
		log.ID = fmt.Sprintf("aud-%d", time.Now().UnixNano())
	}
	if log.CreatedAt.IsZero() {
		log.CreatedAt = time.Now().UTC()
	}
	s.auditLogs[log.OrganizationID] = append(s.auditLogs[log.OrganizationID], log)
	return log, nil
}

func (s *InMemoryStore) ListAuditLogsByOrganization(orgID string, limit int) ([]AuditLog, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	items := s.auditLogs[orgID]
	if limit <= 0 || limit > len(items) {
		limit = len(items)
	}
	out := make([]AuditLog, limit)
	copy(out, items[len(items)-limit:])
	return out, nil
}
