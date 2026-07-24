package storage

import (
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/Jina404/forge/pkg/core"
	"github.com/Jina404/forge/pkg/evidence"
)

// MemoryEvent stores long-term campaign memory and optional vector embedding.
type MemoryEvent struct {
	CampaignID string
	Content    string
	Embedding  []float32
	CreatedAt  time.Time
}

// PostgresStore persists campaigns, vulnerabilities, evidence, and AI memory.
type PostgresStore struct {
	db *sql.DB
}

// NewPostgresStore requires a postgres-compatible SQL driver to be registered.
func NewPostgresStore(dsn string) (*PostgresStore, error) {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, err
	}
	return &PostgresStore{db: db}, nil
}

func (s *PostgresStore) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

func (s *PostgresStore) InitSchema() error {
	queries := []string{
		"CREATE EXTENSION IF NOT EXISTS vector",
		`CREATE TABLE IF NOT EXISTS campaigns (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			target_url TEXT NOT NULL,
			state TEXT NOT NULL,
			created_at TIMESTAMPTZ NOT NULL,
			updated_at TIMESTAMPTZ NOT NULL,
			started_at TIMESTAMPTZ NULL,
			completed_at TIMESTAMPTZ NULL,
			last_error TEXT NOT NULL DEFAULT ''
		)`,
		`CREATE TABLE IF NOT EXISTS vulnerabilities (
			id BIGSERIAL PRIMARY KEY,
			campaign_id TEXT NOT NULL REFERENCES campaigns(id) ON DELETE CASCADE,
			title TEXT NOT NULL,
			severity TEXT NOT NULL,
			confidence DOUBLE PRECISION NOT NULL,
			evidence TEXT NOT NULL,
			impact TEXT NOT NULL,
			remediation TEXT NOT NULL,
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)`,
		`CREATE TABLE IF NOT EXISTS evidence_artifacts (
			id BIGSERIAL PRIMARY KEY,
			campaign_id TEXT NOT NULL REFERENCES campaigns(id) ON DELETE CASCADE,
			vulnerability_name TEXT NOT NULL,
			request TEXT NOT NULL,
			response TEXT NOT NULL,
			payload TEXT NOT NULL,
			timestamp TIMESTAMPTZ NOT NULL,
			screenshot TEXT NOT NULL,
			repro_steps TEXT[] NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS agent_memory (
			id BIGSERIAL PRIMARY KEY,
			campaign_id TEXT NOT NULL REFERENCES campaigns(id) ON DELETE CASCADE,
			content TEXT NOT NULL,
			embedding vector(1536),
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)`,
		`CREATE TABLE IF NOT EXISTS organizations (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			created_at TIMESTAMPTZ NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS users (
			id TEXT PRIMARY KEY,
			organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
			email TEXT NOT NULL UNIQUE,
			password_hash TEXT NOT NULL,
			role TEXT NOT NULL,
			active BOOLEAN NOT NULL DEFAULT TRUE,
			created_at TIMESTAMPTZ NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS projects (
			id TEXT PRIMARY KEY,
			organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
			name TEXT NOT NULL,
			client_name TEXT NOT NULL,
			scope TEXT NOT NULL,
			rules_of_engagement TEXT NOT NULL,
			created_by TEXT NOT NULL,
			created_at TIMESTAMPTZ NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS audit_logs (
			id TEXT PRIMARY KEY,
			organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
			user_id TEXT NOT NULL,
			action TEXT NOT NULL,
			resource TEXT NOT NULL,
			details TEXT NOT NULL,
			created_at TIMESTAMPTZ NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS campaign_tenants (
			campaign_id TEXT PRIMARY KEY REFERENCES campaigns(id) ON DELETE CASCADE,
			organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE
		)`,
		"CREATE INDEX IF NOT EXISTS idx_vulnerabilities_campaign ON vulnerabilities(campaign_id)",
		"CREATE INDEX IF NOT EXISTS idx_evidence_campaign ON evidence_artifacts(campaign_id)",
		"CREATE INDEX IF NOT EXISTS idx_projects_org ON projects(organization_id)",
		"CREATE INDEX IF NOT EXISTS idx_audit_org ON audit_logs(organization_id)",
		"CREATE INDEX IF NOT EXISTS idx_campaign_tenants_org ON campaign_tenants(organization_id)",
	}

	for _, query := range queries {
		if _, err := s.db.Exec(query); err != nil {
			return err
		}
	}
	return nil
}

func (s *PostgresStore) SaveCampaign(campaign core.Campaign) error {
	_, err := s.db.Exec(
		`INSERT INTO campaigns (id, name, target_url, state, created_at, updated_at, started_at, completed_at, last_error)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
		 ON CONFLICT (id) DO UPDATE SET
		 name = EXCLUDED.name,
		 target_url = EXCLUDED.target_url,
		 state = EXCLUDED.state,
		 updated_at = EXCLUDED.updated_at,
		 started_at = EXCLUDED.started_at,
		 completed_at = EXCLUDED.completed_at,
		 last_error = EXCLUDED.last_error`,
		campaign.ID,
		campaign.Name,
		campaign.TargetURL,
		campaign.State,
		campaign.CreatedAt,
		campaign.UpdatedAt,
		campaign.StartedAt,
		campaign.CompletedAt,
		campaign.LastError,
	)
	return err
}

func (s *PostgresStore) GetCampaign(id string) (core.Campaign, error) {
	var campaign core.Campaign
	var state string
	err := s.db.QueryRow(
		`SELECT id, name, target_url, state, created_at, updated_at, started_at, completed_at, last_error
		 FROM campaigns WHERE id = $1`,
		id,
	).Scan(
		&campaign.ID,
		&campaign.Name,
		&campaign.TargetURL,
		&state,
		&campaign.CreatedAt,
		&campaign.UpdatedAt,
		&campaign.StartedAt,
		&campaign.CompletedAt,
		&campaign.LastError,
	)
	if err != nil {
		return core.Campaign{}, err
	}
	campaign.State = core.CampaignState(state)
	return campaign, nil
}

func (s *PostgresStore) SaveVulnerability(campaignID string, vulnerability core.Vulnerability) error {
	_, err := s.db.Exec(
		`INSERT INTO vulnerabilities (campaign_id, title, severity, confidence, evidence, impact, remediation)
		 VALUES ($1,$2,$3,$4,$5,$6,$7)`,
		campaignID,
		vulnerability.Title,
		vulnerability.Severity,
		vulnerability.Confidence,
		vulnerability.Evidence,
		vulnerability.Impact,
		vulnerability.Remediation,
	)
	return err
}

func (s *PostgresStore) ListVulnerabilities(campaignID string) ([]core.Vulnerability, error) {
	rows, err := s.db.Query(
		`SELECT title, severity, confidence, evidence, impact, remediation
		 FROM vulnerabilities WHERE campaign_id = $1 ORDER BY id ASC`,
		campaignID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	result := make([]core.Vulnerability, 0)
	for rows.Next() {
		var vulnerability core.Vulnerability
		if err := rows.Scan(
			&vulnerability.Title,
			&vulnerability.Severity,
			&vulnerability.Confidence,
			&vulnerability.Evidence,
			&vulnerability.Impact,
			&vulnerability.Remediation,
		); err != nil {
			return nil, err
		}
		result = append(result, vulnerability)
	}
	return result, rows.Err()
}

func (s *PostgresStore) SaveArtifact(campaignID string, artifact evidence.Artifact) error {
	_, err := s.db.Exec(
		`INSERT INTO evidence_artifacts
		 (campaign_id, vulnerability_name, request, response, payload, timestamp, screenshot, repro_steps)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
		campaignID,
		artifact.VulnerabilityName,
		artifact.Request,
		artifact.Response,
		artifact.Payload,
		artifact.Timestamp,
		artifact.Screenshot,
		pqTextArray(artifact.ReproSteps),
	)
	return err
}

func (s *PostgresStore) ListArtifacts(campaignID string) ([]evidence.Artifact, error) {
	rows, err := s.db.Query(
		`SELECT campaign_id, vulnerability_name, request, response, payload, timestamp, screenshot, repro_steps
		 FROM evidence_artifacts WHERE campaign_id = $1 ORDER BY id ASC`,
		campaignID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	result := make([]evidence.Artifact, 0)
	for rows.Next() {
		var artifact evidence.Artifact
		var repro []byte
		if err := rows.Scan(
			&artifact.CampaignID,
			&artifact.VulnerabilityName,
			&artifact.Request,
			&artifact.Response,
			&artifact.Payload,
			&artifact.Timestamp,
			&artifact.Screenshot,
			&repro,
		); err != nil {
			return nil, err
		}
		artifact.ReproSteps = parseArrayText(string(repro))
		result = append(result, artifact)
	}
	return result, rows.Err()
}

func (s *PostgresStore) SaveCampaignTenant(campaignID string, organizationID string) error {
	_, err := s.db.Exec(
		`INSERT INTO campaign_tenants (campaign_id, organization_id)
		 VALUES ($1,$2)
		 ON CONFLICT (campaign_id) DO UPDATE SET organization_id = EXCLUDED.organization_id`,
		campaignID,
		organizationID,
	)
	return err
}

func (s *PostgresStore) GetCampaignTenant(campaignID string) (string, error) {
	var organizationID string
	err := s.db.QueryRow(`SELECT organization_id FROM campaign_tenants WHERE campaign_id = $1`, campaignID).Scan(&organizationID)
	if err != nil {
		return "", err
	}
	return organizationID, nil
}

func (s *PostgresStore) SaveMemoryEvent(campaignID string, content string, embedding []float32) error {
	embeddingLiteral := pgVectorLiteral(embedding)
	_, err := s.db.Exec(
		`INSERT INTO agent_memory (campaign_id, content, embedding) VALUES ($1,$2,$3)`,
		campaignID,
		content,
		embeddingLiteral,
	)
	return err
}

func (s *PostgresStore) ListMemoryEvents(campaignID string, limit int) ([]MemoryEvent, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := s.db.Query(
		`SELECT campaign_id, content, created_at FROM agent_memory
		 WHERE campaign_id = $1 ORDER BY id DESC LIMIT $2`,
		campaignID,
		limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	result := make([]MemoryEvent, 0)
	for rows.Next() {
		var event MemoryEvent
		if err := rows.Scan(&event.CampaignID, &event.Content, &event.CreatedAt); err != nil {
			return nil, err
		}
		result = append(result, event)
	}
	return result, rows.Err()
}

func pgVectorLiteral(values []float32) string {
	if len(values) == 0 {
		return "[]"
	}
	parts := make([]string, 0, len(values))
	for _, value := range values {
		parts = append(parts, fmt.Sprintf("%f", value))
	}
	return "[" + strings.Join(parts, ",") + "]"
}

func pqTextArray(values []string) string {
	if len(values) == 0 {
		return "{}"
	}
	escaped := make([]string, 0, len(values))
	for _, value := range values {
		v := strings.ReplaceAll(value, "\\", "\\\\")
		v = strings.ReplaceAll(v, `"`, `\\"`)
		escaped = append(escaped, `"`+v+`"`)
	}
	return "{" + strings.Join(escaped, ",") + "}"
}

func parseArrayText(input string) []string {
	trimmed := strings.TrimSpace(input)
	if trimmed == "" || trimmed == "{}" {
		return []string{}
	}
	trimmed = strings.TrimPrefix(trimmed, "{")
	trimmed = strings.TrimSuffix(trimmed, "}")
	if strings.TrimSpace(trimmed) == "" {
		return []string{}
	}
	parts := strings.Split(trimmed, ",")
	for i, part := range parts {
		parts[i] = strings.Trim(part, `"`)
	}
	return parts
}

func (s *PostgresStore) CountOrganizations() int {
	var count int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM organizations`).Scan(&count)
	if err != nil {
		return 0
	}
	return count
}

func (s *PostgresStore) CreateOrganization(org Organization) (Organization, error) {
	if org.ID == "" {
		org.ID = fmt.Sprintf("org-%d", time.Now().UnixNano())
	}
	if org.CreatedAt.IsZero() {
		org.CreatedAt = time.Now().UTC()
	}
	_, err := s.db.Exec(
		`INSERT INTO organizations (id, name, created_at) VALUES ($1,$2,$3)`,
		org.ID,
		org.Name,
		org.CreatedAt,
	)
	return org, err
}

func (s *PostgresStore) ListOrganizations() ([]Organization, error) {
	rows, err := s.db.Query(`SELECT id, name, created_at FROM organizations ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]Organization, 0)
	for rows.Next() {
		var org Organization
		if err := rows.Scan(&org.ID, &org.Name, &org.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, org)
	}
	return out, rows.Err()
}

func (s *PostgresStore) GetOrganization(id string) (Organization, error) {
	var org Organization
	err := s.db.QueryRow(`SELECT id, name, created_at FROM organizations WHERE id = $1`, id).Scan(&org.ID, &org.Name, &org.CreatedAt)
	if err != nil {
		return Organization{}, err
	}
	return org, nil
}

func (s *PostgresStore) CreateUser(user User) (User, error) {
	if user.ID == "" {
		user.ID = fmt.Sprintf("usr-%d", time.Now().UnixNano())
	}
	if user.CreatedAt.IsZero() {
		user.CreatedAt = time.Now().UTC()
	}
	if !user.Active {
		user.Active = true
	}
	_, err := s.db.Exec(
		`INSERT INTO users (id, organization_id, email, password_hash, role, active, created_at)
		 VALUES ($1,$2,$3,$4,$5,$6,$7)`,
		user.ID,
		user.OrganizationID,
		user.Email,
		user.PasswordHash,
		user.Role,
		user.Active,
		user.CreatedAt,
	)
	return user, err
}

func (s *PostgresStore) GetUserByEmail(email string) (User, error) {
	var user User
	err := s.db.QueryRow(
		`SELECT id, organization_id, email, password_hash, role, active, created_at
		 FROM users WHERE email = $1`,
		email,
	).Scan(
		&user.ID,
		&user.OrganizationID,
		&user.Email,
		&user.PasswordHash,
		&user.Role,
		&user.Active,
		&user.CreatedAt,
	)
	if err != nil {
		return User{}, err
	}
	return user, nil
}

func (s *PostgresStore) ListUsersByOrganization(orgID string) ([]User, error) {
	rows, err := s.db.Query(
		`SELECT id, organization_id, email, password_hash, role, active, created_at
		 FROM users WHERE organization_id = $1 ORDER BY created_at DESC`,
		orgID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]User, 0)
	for rows.Next() {
		var user User
		if err := rows.Scan(&user.ID, &user.OrganizationID, &user.Email, &user.PasswordHash, &user.Role, &user.Active, &user.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, user)
	}
	return out, rows.Err()
}

func (s *PostgresStore) CreateProject(project Project) (Project, error) {
	if project.ID == "" {
		project.ID = fmt.Sprintf("prj-%d", time.Now().UnixNano())
	}
	if project.CreatedAt.IsZero() {
		project.CreatedAt = time.Now().UTC()
	}
	_, err := s.db.Exec(
		`INSERT INTO projects
		 (id, organization_id, name, client_name, scope, rules_of_engagement, created_by, created_at)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
		project.ID,
		project.OrganizationID,
		project.Name,
		project.ClientName,
		project.Scope,
		project.RulesOfEngagement,
		project.CreatedBy,
		project.CreatedAt,
	)
	return project, err
}

func (s *PostgresStore) ListProjectsByOrganization(orgID string) ([]Project, error) {
	rows, err := s.db.Query(
		`SELECT id, organization_id, name, client_name, scope, rules_of_engagement, created_by, created_at
		 FROM projects WHERE organization_id = $1 ORDER BY created_at DESC`,
		orgID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]Project, 0)
	for rows.Next() {
		var project Project
		if err := rows.Scan(
			&project.ID,
			&project.OrganizationID,
			&project.Name,
			&project.ClientName,
			&project.Scope,
			&project.RulesOfEngagement,
			&project.CreatedBy,
			&project.CreatedAt,
		); err != nil {
			return nil, err
		}
		out = append(out, project)
	}
	return out, rows.Err()
}

func (s *PostgresStore) AppendAuditLog(log AuditLog) (AuditLog, error) {
	if log.ID == "" {
		log.ID = fmt.Sprintf("aud-%d", time.Now().UnixNano())
	}
	if log.CreatedAt.IsZero() {
		log.CreatedAt = time.Now().UTC()
	}
	_, err := s.db.Exec(
		`INSERT INTO audit_logs (id, organization_id, user_id, action, resource, details, created_at)
		 VALUES ($1,$2,$3,$4,$5,$6,$7)`,
		log.ID,
		log.OrganizationID,
		log.UserID,
		log.Action,
		log.Resource,
		log.Details,
		log.CreatedAt,
	)
	return log, err
}

func (s *PostgresStore) ListAuditLogsByOrganization(orgID string, limit int) ([]AuditLog, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.db.Query(
		`SELECT id, organization_id, user_id, action, resource, details, created_at
		 FROM audit_logs WHERE organization_id = $1 ORDER BY created_at DESC LIMIT $2`,
		orgID,
		limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]AuditLog, 0)
	for rows.Next() {
		var log AuditLog
		if err := rows.Scan(&log.ID, &log.OrganizationID, &log.UserID, &log.Action, &log.Resource, &log.Details, &log.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, log)
	}
	return out, rows.Err()
}
