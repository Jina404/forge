package api

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Jina404/forge/pkg/agent"
	"github.com/Jina404/forge/pkg/browser"
	"github.com/Jina404/forge/pkg/config"
	"github.com/Jina404/forge/pkg/core"
	"github.com/Jina404/forge/pkg/engine"
	"github.com/Jina404/forge/pkg/evidence"
	"github.com/Jina404/forge/pkg/intelligence"
	"github.com/Jina404/forge/pkg/reporting"
	"github.com/Jina404/forge/pkg/storage"
)

// Server exposes basic control-plane APIs.
type Server struct {
	mux           *http.ServeMux
	cfg           config.AppConfig
	store         dataStore
	runnerFactory core.NewRunnerFunc
	planner       core.PlannerService
	screenshotter core.ScreenshotService
}

type dataStore interface {
	core.CampaignStore
	core.VulnerabilityStore
	core.EvidenceStore
	SaveCampaignTenant(campaignID string, organizationID string) error
	GetCampaignTenant(campaignID string) (string, error)
	CountOrganizations() int
	CreateOrganization(org storage.Organization) (storage.Organization, error)
	ListOrganizations() ([]storage.Organization, error)
	GetOrganization(id string) (storage.Organization, error)
	CreateUser(user storage.User) (storage.User, error)
	GetUserByEmail(email string) (storage.User, error)
	ListUsersByOrganization(orgID string) ([]storage.User, error)
	CreateProject(project storage.Project) (storage.Project, error)
	ListProjectsByOrganization(orgID string) ([]storage.Project, error)
	AppendAuditLog(log storage.AuditLog) (storage.AuditLog, error)
	ListAuditLogsByOrganization(orgID string, limit int) ([]storage.AuditLog, error)
}

type authSession struct {
	UserID         string    `json:"user_id"`
	OrganizationID string    `json:"organization_id"`
	Role           string    `json:"role"`
	ExpiresAt      time.Time `json:"expires_at"`
}

type campaignCreateRequest struct {
	Name            string  `json:"name"`
	TargetURL       string  `json:"target_url"`
	Method          string  `json:"method"`
	Concurrency     int     `json:"concurrency"`
	DurationSeconds int     `json:"duration_seconds"`
	TimeoutSeconds  int     `json:"timeout_seconds"`
	FuzzRatio       float64 `json:"fuzz_ratio"`
	FuzzParam       string  `json:"fuzz_param"`
	PayloadFile     string  `json:"payload_file"`
	Baseline        bool    `json:"baseline"`
}

type bootstrapRequest struct {
	OrganizationName string `json:"organization_name"`
	AdminEmail       string `json:"admin_email"`
	AdminPassword    string `json:"admin_password"`
}

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type createOrganizationRequest struct {
	Name string `json:"name"`
}

type createUserRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	Role     string `json:"role"`
}

type createProjectRequest struct {
	Name              string `json:"name"`
	ClientName        string `json:"client_name"`
	Scope             string `json:"scope"`
	RulesOfEngagement string `json:"rules_of_engagement"`
}

// NewServer builds a default API server with in-memory storage.
func NewServer() *Server {
	return NewServerWithConfig(config.Default(), storage.NewInMemoryStore())
}

// NewServerWithConfig builds an API server with custom config and store.
func NewServerWithConfig(cfg config.AppConfig, store dataStore) *Server {
	mux := http.NewServeMux()
	s := &Server{
		mux:            mux,
		cfg:            cfg,
		store:          store,
		runnerFactory: func(cfg engine.Config) (core.EngineRunner, error) { return engine.NewRunner(cfg) },
	}
	if strings.TrimSpace(cfg.AIServiceURL) != "" {
		s.planner = agent.NewPlannerClient(cfg.AIServiceURL, cfg.RequestTimeout)
	}
	if strings.TrimSpace(cfg.BrowserServiceURL) != "" {
		s.screenshotter = browser.NewClient(cfg.BrowserServiceURL, cfg.RequestTimeout)
	}
	s.registerRoutes()
	return s
}

func (s *Server) Handler() http.Handler {
	return s.mux
}

func (s *Server) registerRoutes() {
	s.mux.HandleFunc("/bootstrap", s.handleBootstrap)
	s.mux.HandleFunc("/auth/login", s.handleLogin)
	s.mux.HandleFunc("/organizations", s.handleOrganizations)
	s.mux.HandleFunc("/organizations/", s.handleOrganizationRoutes)

	s.mux.HandleFunc("/campaigns", s.handleCampaignCreate)
	s.mux.HandleFunc("/campaigns/", s.handleCampaignRoutes)

	s.mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":    "ok",
			"component": "forge-api",
			"time":      time.Now().UTC().Format(time.RFC3339),
		})
	})
}

func (s *Server) handleBootstrap(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	providedToken := strings.TrimSpace(r.Header.Get("X-Forge-Bootstrap-Token"))
	if subtle.ConstantTimeCompare([]byte(providedToken), []byte(s.cfg.BootstrapToken)) != 1 {
		writeError(w, http.StatusUnauthorized, "invalid bootstrap token")
		return
	}

	if s.store.CountOrganizations() > 0 {
		writeError(w, http.StatusConflict, "bootstrap already completed")
		return
	}

	var request bootstrapRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if strings.TrimSpace(request.OrganizationName) == "" || strings.TrimSpace(request.AdminEmail) == "" || strings.TrimSpace(request.AdminPassword) == "" {
		writeError(w, http.StatusBadRequest, "organization_name, admin_email, and admin_password are required")
		return
	}

	org, err := s.store.CreateOrganization(storage.Organization{Name: request.OrganizationName})
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	user, err := s.store.CreateUser(storage.User{
		OrganizationID: org.ID,
		Email:          strings.ToLower(strings.TrimSpace(request.AdminEmail)),
		PasswordHash:   hashPassword(request.AdminPassword),
		Role:           storage.RoleAdmin,
		Active:         true,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	_, _ = s.store.AppendAuditLog(storage.AuditLog{
		OrganizationID: org.ID,
		UserID:         user.ID,
		Action:         "bootstrap",
		Resource:       "organization",
		Details:        "Initial admin and organization created",
	})

	writeJSON(w, http.StatusCreated, map[string]any{"organization": org, "admin_user": sanitizeUser(user)})
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var request loginRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	user, err := s.store.GetUserByEmail(strings.ToLower(strings.TrimSpace(request.Email)))
	if err != nil || !user.Active {
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}

	if subtle.ConstantTimeCompare([]byte(user.PasswordHash), []byte(hashPassword(request.Password))) != 1 {
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}

	expiresAt := time.Now().UTC().Add(time.Duration(s.cfg.SessionTTLSeconds) * time.Second)
	token, err := issueSignedToken(s.cfg.AuthSigningKey, authSession{
		UserID:         user.ID,
		OrganizationID: user.OrganizationID,
		Role:           user.Role,
		ExpiresAt:      expiresAt,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to generate auth token")
		return
	}

	_, _ = s.store.AppendAuditLog(storage.AuditLog{
		OrganizationID: user.OrganizationID,
		UserID:         user.ID,
		Action:         "login",
		Resource:       "auth",
		Details:        "User authenticated",
	})

	writeJSON(w, http.StatusOK, map[string]any{"token": token, "user": sanitizeUser(user), "expires_at": expiresAt})
}

func (s *Server) handleOrganizations(w http.ResponseWriter, r *http.Request) {
	s.withSession(w, r, []string{storage.RoleAdmin, storage.RolePentester, storage.RoleViewer}, func(session authSession) {
		switch r.Method {
		case http.MethodGet:
			org, err := s.store.GetOrganization(session.OrganizationID)
			if err != nil {
				writeError(w, http.StatusNotFound, err.Error())
				return
			}
			writeJSON(w, http.StatusOK, []storage.Organization{org})
		case http.MethodPost:
			if session.Role != storage.RoleAdmin {
				writeError(w, http.StatusForbidden, "admin role required")
				return
			}
			var request createOrganizationRequest
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				writeError(w, http.StatusBadRequest, "invalid JSON body")
				return
			}
			if strings.TrimSpace(request.Name) == "" {
				writeError(w, http.StatusBadRequest, "name is required")
				return
			}
			org, err := s.store.CreateOrganization(storage.Organization{Name: request.Name})
			if err != nil {
				writeError(w, http.StatusInternalServerError, err.Error())
				return
			}
			_, _ = s.store.AppendAuditLog(storage.AuditLog{
				OrganizationID: session.OrganizationID,
				UserID:         session.UserID,
				Action:         "create_organization",
				Resource:       "organization",
				Details:        org.ID,
			})
			writeJSON(w, http.StatusCreated, org)
		default:
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		}
	})
}

func (s *Server) handleOrganizationRoutes(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/organizations/")
	parts := strings.Split(path, "/")
	if len(parts) == 0 || strings.TrimSpace(parts[0]) == "" {
		writeError(w, http.StatusNotFound, "organization ID missing")
		return
	}
	orgID := parts[0]

	s.withSession(w, r, []string{storage.RoleAdmin, storage.RolePentester, storage.RoleViewer}, func(session authSession) {
		if session.OrganizationID != orgID {
			writeError(w, http.StatusForbidden, "cross-organization access denied")
			return
		}

		if len(parts) == 1 {
			if r.Method != http.MethodGet {
				writeError(w, http.StatusMethodNotAllowed, "method not allowed")
				return
			}
			org, err := s.store.GetOrganization(orgID)
			if err != nil {
				writeError(w, http.StatusNotFound, err.Error())
				return
			}
			writeJSON(w, http.StatusOK, org)
			return
		}

		switch parts[1] {
		case "users":
			s.handleOrganizationUsers(w, r, session, orgID)
		case "projects":
			s.handleOrganizationProjects(w, r, session, orgID)
		case "audit-logs":
			s.handleOrganizationAuditLogs(w, r, session, orgID)
		default:
			writeError(w, http.StatusNotFound, "route not found")
		}
	})
}

func (s *Server) handleOrganizationUsers(w http.ResponseWriter, r *http.Request, session authSession, orgID string) {
	switch r.Method {
	case http.MethodGet:
		if session.Role == storage.RoleViewer {
			writeError(w, http.StatusForbidden, "insufficient role")
			return
		}
		users, err := s.store.ListUsersByOrganization(orgID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		cleaned := make([]storage.User, 0, len(users))
		for _, user := range users {
			cleaned = append(cleaned, sanitizeUser(user))
		}
		writeJSON(w, http.StatusOK, cleaned)
	case http.MethodPost:
		if session.Role != storage.RoleAdmin {
			writeError(w, http.StatusForbidden, "admin role required")
			return
		}
		var request createUserRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON body")
			return
		}
		role := strings.ToLower(strings.TrimSpace(request.Role))
		if role != storage.RoleAdmin && role != storage.RolePentester && role != storage.RoleViewer {
			writeError(w, http.StatusBadRequest, "role must be admin, pentester, or viewer")
			return
		}
		if strings.TrimSpace(request.Email) == "" || strings.TrimSpace(request.Password) == "" {
			writeError(w, http.StatusBadRequest, "email and password are required")
			return
		}
		user, err := s.store.CreateUser(storage.User{
			OrganizationID: orgID,
			Email:          strings.ToLower(strings.TrimSpace(request.Email)),
			PasswordHash:   hashPassword(request.Password),
			Role:           role,
			Active:         true,
		})
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		_, _ = s.store.AppendAuditLog(storage.AuditLog{
			OrganizationID: orgID,
			UserID:         session.UserID,
			Action:         "create_user",
			Resource:       "user",
			Details:        user.Email,
		})
		writeJSON(w, http.StatusCreated, sanitizeUser(user))
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *Server) handleOrganizationProjects(w http.ResponseWriter, r *http.Request, session authSession, orgID string) {
	switch r.Method {
	case http.MethodGet:
		projects, err := s.store.ListProjectsByOrganization(orgID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, projects)
	case http.MethodPost:
		if session.Role == storage.RoleViewer {
			writeError(w, http.StatusForbidden, "insufficient role")
			return
		}
		var request createProjectRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON body")
			return
		}
		if strings.TrimSpace(request.Name) == "" || strings.TrimSpace(request.ClientName) == "" {
			writeError(w, http.StatusBadRequest, "name and client_name are required")
			return
		}
		project, err := s.store.CreateProject(storage.Project{
			OrganizationID:    orgID,
			Name:              request.Name,
			ClientName:        request.ClientName,
			Scope:             request.Scope,
			RulesOfEngagement: request.RulesOfEngagement,
			CreatedBy:         session.UserID,
		})
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		_, _ = s.store.AppendAuditLog(storage.AuditLog{
			OrganizationID: orgID,
			UserID:         session.UserID,
			Action:         "create_project",
			Resource:       "project",
			Details:        project.ID,
		})
		writeJSON(w, http.StatusCreated, project)
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *Server) handleOrganizationAuditLogs(w http.ResponseWriter, r *http.Request, session authSession, orgID string) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if session.Role != storage.RoleAdmin {
		writeError(w, http.StatusForbidden, "admin role required")
		return
	}
	limit := parseIntQuery(r, "limit", 100)
	logs, err := s.store.ListAuditLogsByOrganization(orgID, limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, logs)
}

func (s *Server) handleCampaignCreate(w http.ResponseWriter, r *http.Request) {
	s.withSession(w, r, []string{storage.RoleAdmin, storage.RolePentester}, func(session authSession) {
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}

		var request campaignCreateRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON body")
			return
		}

	if request.Method == "" {
		request.Method = "GET"
	}
	if request.Concurrency <= 0 {
		request.Concurrency = 100
	}
	if request.DurationSeconds <= 0 {
		request.DurationSeconds = 10
	}
	if request.TimeoutSeconds <= 0 {
		request.TimeoutSeconds = 5
	}

		campaignID := fmt.Sprintf("cmp-%d", time.Now().UnixNano())
		campaign, err := core.NewCampaign(campaignID, request.Name, request.TargetURL)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}

		orchestratorOptions := make([]core.OrchestratorOption, 0)
		if s.planner != nil {
			orchestratorOptions = append(orchestratorOptions, core.WithPlanner(s.planner))
		}
		if s.screenshotter != nil {
			orchestratorOptions = append(orchestratorOptions, core.WithScreenshotter(s.screenshotter))
		}

		orchestrator, err := core.NewOrchestrator(
			s.runnerFactory,
			s.store,
			s.store,
			s.store,
			evidence.NewCollector(),
			core.DefaultWorkflow(),
			orchestratorOptions...,
		)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}

		result, err := orchestrator.ExecuteCampaign(campaign, engine.Config{
			TargetURL:         request.TargetURL,
			Method:            request.Method,
			Concurrency:       request.Concurrency,
			Duration:          time.Duration(request.DurationSeconds) * time.Second,
			Timeout:           time.Duration(request.TimeoutSeconds) * time.Second,
			Headers:           map[string]string{"User-Agent": "Forge-Agent/1.0"},
			FuzzRatio:         request.FuzzRatio,
			FuzzParam:         request.FuzzParam,
			PayloadFile:       request.PayloadFile,
			EstablishBaseline: request.Baseline,
		})
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}

		if err := s.store.SaveCampaignTenant(campaign.ID, session.OrganizationID); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}

		if postgresStore, ok := s.store.(*storage.PostgresStore); ok {
			_ = postgresStore.SaveMemoryEvent(
				campaign.ID,
				fmt.Sprintf("Campaign finished with %d vulnerabilities", len(result.Vulnerabilities)),
				nil,
			)
		}

		_, _ = s.store.AppendAuditLog(storage.AuditLog{
			OrganizationID: session.OrganizationID,
			UserID:         session.UserID,
			Action:         "run_campaign",
			Resource:       "campaign",
			Details:        campaign.ID,
		})

		writeJSON(w, http.StatusCreated, map[string]any{
			"campaign":        result.Campaign,
			"metrics":         result.Metrics,
			"vulnerabilities": result.Vulnerabilities,
			"artifacts":       result.Artifacts,
		})
	})
}

func (s *Server) handleCampaignRoutes(w http.ResponseWriter, r *http.Request) {
	s.withSession(w, r, []string{storage.RoleAdmin, storage.RolePentester, storage.RoleViewer}, func(session authSession) {
		path := strings.TrimPrefix(r.URL.Path, "/campaigns/")
		parts := strings.Split(path, "/")
		if len(parts) == 0 || strings.TrimSpace(parts[0]) == "" {
			writeError(w, http.StatusNotFound, "campaign ID missing")
			return
		}
		campaignID := parts[0]

		if err := s.ensureCampaignAccess(session.OrganizationID, campaignID); err != nil {
			writeError(w, http.StatusForbidden, err.Error())
			return
		}

		if len(parts) == 1 {
			s.handleCampaignGet(w, r, campaignID)
			return
		}

		switch parts[1] {
		case "findings":
			s.handleCampaignFindings(w, r, campaignID)
		case "evidence":
			s.handleCampaignEvidence(w, r, campaignID)
		case "memory":
			s.handleCampaignMemory(w, r, campaignID)
		case "reports":
			if len(parts) < 3 {
				writeError(w, http.StatusNotFound, "report type missing")
				return
			}
			s.handleCampaignReport(w, r, campaignID, parts[2])
		default:
			writeError(w, http.StatusNotFound, "route not found")
		}
	})
}

func (s *Server) handleCampaignGet(w http.ResponseWriter, r *http.Request, campaignID string) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	campaign, err := s.store.GetCampaign(campaignID)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, campaign)
}

func (s *Server) handleCampaignFindings(w http.ResponseWriter, r *http.Request, campaignID string) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	findings, err := s.store.ListVulnerabilities(campaignID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, findings)
}

func (s *Server) handleCampaignEvidence(w http.ResponseWriter, r *http.Request, campaignID string) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	artifacts, err := s.store.ListArtifacts(campaignID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, artifacts)
}

func (s *Server) handleCampaignMemory(w http.ResponseWriter, r *http.Request, campaignID string) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	postgresStore, ok := s.store.(*storage.PostgresStore)
	if !ok {
		writeError(w, http.StatusNotImplemented, "memory history is available when postgres backend is enabled")
		return
	}
	limit := 50
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err == nil && parsed > 0 {
			limit = parsed
		}
	}
	events, err := postgresStore.ListMemoryEvents(campaignID, limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, events)
}

func (s *Server) handleCampaignReport(w http.ResponseWriter, r *http.Request, campaignID string, reportType string) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	vulnerabilities, err := s.store.ListVulnerabilities(campaignID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	artifacts, err := s.store.ListArtifacts(campaignID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	switch reportType {
	case "executive":
		report := buildExecutiveReport(campaignID, vulnerabilities)
		writeJSON(w, http.StatusOK, report)
	case "technical":
		report := reporting.TechnicalReport{
			CampaignID:      campaignID,
			Vulnerabilities: vulnerabilities,
			Artifacts:       artifacts,
			RemediationPlan: []string{"Prioritize critical vulnerabilities first", "Retest after remediation"},
		}
		writeJSON(w, http.StatusOK, report)
	default:
		writeError(w, http.StatusNotFound, "unknown report type")
	}
}

func buildExecutiveReport(campaignID string, vulnerabilities []core.Vulnerability) reporting.ExecutiveReport {
	critical := 0
	totalRisk := 0
	for _, vulnerability := range vulnerabilities {
		if strings.EqualFold(vulnerability.Severity, "critical") {
			critical++
		}
		totalRisk += intelligence.RiskScore(vulnerability.Severity, vulnerability.Confidence)
	}
	securityScore := 100
	if len(vulnerabilities) > 0 {
		avgRisk := totalRisk / len(vulnerabilities)
		securityScore = 100 - avgRisk
	}
	if securityScore < 0 {
		securityScore = 0
	}

	maxItems := 5
	if len(vulnerabilities) < maxItems {
		maxItems = len(vulnerabilities)
	}

	return reporting.ExecutiveReport{
		CampaignID:       campaignID,
		SecurityScore:    securityScore,
		CriticalFindings: critical,
		TopFindings:      vulnerabilities[:maxItems],
		BusinessImpact:   []string{"Operational disruption risk", "Potential data exposure", "Compliance and reputational impact"},
	}
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}

func parseIntQuery(r *http.Request, key string, fallback int) int {
	raw := strings.TrimSpace(r.URL.Query().Get(key))
	if raw == "" {
		return fallback
	}
	value, err := strconv.Atoi(raw)
	if err != nil {
		return fallback
	}
	return value
}

func sanitizeUser(user storage.User) storage.User {
	user.PasswordHash = ""
	return user
}

func hashPassword(input string) string {
	sum := sha256.Sum256([]byte(input))
	return fmt.Sprintf("%x", sum)
}

func (s *Server) withSession(w http.ResponseWriter, r *http.Request, roles []string, handler func(authSession)) {
	token := extractBearerToken(r.Header.Get("Authorization"))
	if token == "" {
		writeError(w, http.StatusUnauthorized, "missing bearer token")
		return
	}

	session, err := parseSignedToken(s.cfg.AuthSigningKey, token)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid or expired session")
		return
	}
	if time.Now().UTC().After(session.ExpiresAt) {
		writeError(w, http.StatusUnauthorized, "session expired")
		return
	}

	if !roleAllowed(session.Role, roles) {
		writeError(w, http.StatusForbidden, "insufficient role")
		return
	}
	handler(session)
}

func (s *Server) ensureCampaignAccess(organizationID string, campaignID string) error {
	ownerOrgID, err := s.store.GetCampaignTenant(campaignID)
	if err != nil {
		return fmt.Errorf("campaign access mapping missing")
	}
	if ownerOrgID != organizationID {
		return fmt.Errorf("campaign belongs to a different organization")
	}
	return nil
}

func roleAllowed(role string, allowed []string) bool {
	for _, candidate := range allowed {
		if strings.EqualFold(role, candidate) {
			return true
		}
	}
	return false
}

func extractBearerToken(header string) string {
	parts := strings.SplitN(strings.TrimSpace(header), " ", 2)
	if len(parts) != 2 {
		return ""
	}
	if !strings.EqualFold(parts[0], "Bearer") {
		return ""
	}
	return strings.TrimSpace(parts[1])
}

func issueSignedToken(signingKey string, session authSession) (string, error) {
	payload := map[string]any{
		"user_id":         session.UserID,
		"organization_id": session.OrganizationID,
		"role":            session.Role,
		"exp":             session.ExpiresAt.Unix(),
	}
	rawPayload, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	payloadPart := base64.RawURLEncoding.EncodeToString(rawPayload)
	signature := signPayload(signingKey, payloadPart)
	return payloadPart + "." + signature, nil
}

func parseSignedToken(signingKey string, token string) (authSession, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return authSession{}, fmt.Errorf("invalid token format")
	}
	payloadPart := parts[0]
	signaturePart := parts[1]
	expectedSig := signPayload(signingKey, payloadPart)
	if subtle.ConstantTimeCompare([]byte(signaturePart), []byte(expectedSig)) != 1 {
		return authSession{}, fmt.Errorf("invalid token signature")
	}

	rawPayload, err := base64.RawURLEncoding.DecodeString(payloadPart)
	if err != nil {
		return authSession{}, err
	}

	var payload map[string]any
	if err := json.Unmarshal(rawPayload, &payload); err != nil {
		return authSession{}, err
	}

	userID, _ := payload["user_id"].(string)
	orgID, _ := payload["organization_id"].(string)
	role, _ := payload["role"].(string)
	expValue, ok := payload["exp"].(float64)
	if !ok {
		return authSession{}, fmt.Errorf("missing exp in token")
	}

	if userID == "" || orgID == "" || role == "" {
		return authSession{}, fmt.Errorf("invalid token payload")
	}

	return authSession{
		UserID:         userID,
		OrganizationID: orgID,
		Role:           role,
		ExpiresAt:      time.Unix(int64(expValue), 0).UTC(),
	}, nil
}

func signPayload(signingKey string, payloadPart string) string {
	mac := hmac.New(sha256.New, []byte(signingKey))
	_, _ = mac.Write([]byte(payloadPart))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}
