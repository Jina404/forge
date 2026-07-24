package storage

import "time"

const (
	RoleAdmin     = "admin"
	RolePentester = "pentester"
	RoleViewer    = "viewer"
)

// CampaignRecord is a persistence-friendly campaign view.
type CampaignRecord struct {
	ID          string
	Name        string
	TargetURL   string
	State       string
	CreatedAt   time.Time
	UpdatedAt   time.Time
	StartedAt   *time.Time
	CompletedAt *time.Time
	LastError   string
}

// VulnerabilityRecord is a persistence-friendly vulnerability view.
type VulnerabilityRecord struct {
	CampaignID  string
	Title       string
	Severity    string
	Confidence  float64
	Evidence    string
	Impact      string
	Remediation string
}

// Organization represents a tenant boundary.
type Organization struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
}

// User represents an authenticated platform identity.
type User struct {
	ID             string    `json:"id"`
	OrganizationID string    `json:"organization_id"`
	Email          string    `json:"email"`
	PasswordHash   string    `json:"-"`
	Role           string    `json:"role"`
	Active         bool      `json:"active"`
	CreatedAt      time.Time `json:"created_at"`
}

// Project represents a scoped customer engagement.
type Project struct {
	ID                string    `json:"id"`
	OrganizationID    string    `json:"organization_id"`
	Name              string    `json:"name"`
	ClientName        string    `json:"client_name"`
	Scope             string    `json:"scope"`
	RulesOfEngagement string    `json:"rules_of_engagement"`
	CreatedBy         string    `json:"created_by"`
	CreatedAt         time.Time `json:"created_at"`
}

// AuditLog tracks high-value actions for accountability.
type AuditLog struct {
	ID             string    `json:"id"`
	OrganizationID string    `json:"organization_id"`
	UserID         string    `json:"user_id"`
	Action         string    `json:"action"`
	Resource       string    `json:"resource"`
	Details        string    `json:"details"`
	CreatedAt      time.Time `json:"created_at"`
}
