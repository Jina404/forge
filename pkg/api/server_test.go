package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Jina404/forge/pkg/config"
	"github.com/Jina404/forge/pkg/core"
	"github.com/Jina404/forge/pkg/evidence"
	"github.com/Jina404/forge/pkg/storage"
)

func TestHealthz(t *testing.T) {
	server := NewServer()
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	res := httptest.NewRecorder()
	server.Handler().ServeHTTP(res, req)

	if res.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", res.Code)
	}
}

func TestFindingsAndTechnicalReport(t *testing.T) {
	store := storage.NewInMemoryStore()
	cfg := config.Default()
	apiServer := NewServerWithConfig(cfg, store)
	token := bootstrapAndLogin(t, apiServer, cfg)

	orgs, err := store.ListOrganizations()
	if err != nil || len(orgs) == 0 {
		t.Fatalf("expected bootstrap organization, got err=%v", err)
	}
	orgID := orgs[0].ID

	campaign, err := core.NewCampaign("cmp-1", "Campaign", "https://example.com")
	if err != nil {
		t.Fatalf("failed to create campaign: %v", err)
	}
	if err := store.SaveCampaign(campaign); err != nil {
		t.Fatalf("failed to save campaign: %v", err)
	}
	_ = store.SaveVulnerability("cmp-1", core.Vulnerability{
		Title:       "SQL Injection",
		Severity:    "critical",
		Confidence:  0.95,
		Evidence:    "error text",
		Impact:      "data exfiltration",
		Remediation: "parameterized queries",
	})
	_ = store.SaveArtifact("cmp-1", evidence.Artifact{
		CampaignID:        "cmp-1",
		VulnerabilityName: "SQL Injection",
		Request:           "GET /",
		Response:          "500",
		Payload:           "' OR '1'='1",
		Timestamp:         time.Now().UTC(),
		Screenshot:        "artifacts/shot.png",
		ReproSteps:        []string{"step1", "step2"},
	})
	_ = store.SaveCampaignTenant("cmp-1", orgID)

	findingsReq := httptest.NewRequest(http.MethodGet, "/campaigns/cmp-1/findings", nil)
	findingsReq.Header.Set("Authorization", "Bearer "+token)
	findingsRes := httptest.NewRecorder()
	apiServer.Handler().ServeHTTP(findingsRes, findingsReq)
	if findingsRes.Code != http.StatusOK {
		t.Fatalf("expected 200 for findings, got %d", findingsRes.Code)
	}

	reportReq := httptest.NewRequest(http.MethodGet, "/campaigns/cmp-1/reports/technical", nil)
	reportReq.Header.Set("Authorization", "Bearer "+token)
	reportRes := httptest.NewRecorder()
	apiServer.Handler().ServeHTTP(reportRes, reportReq)
	if reportRes.Code != http.StatusOK {
		t.Fatalf("expected 200 for technical report, got %d", reportRes.Code)
	}

	var payload map[string]any
	if err := json.Unmarshal(reportRes.Body.Bytes(), &payload); err != nil {
		t.Fatalf("failed to decode report JSON: %v", err)
	}
	if payload["campaign_id"] != "cmp-1" {
		t.Fatalf("unexpected campaign_id: %v", payload["campaign_id"])
	}
}

func TestBootstrapLoginAndEnterpriseRoutes(t *testing.T) {
	store := storage.NewInMemoryStore()
	cfg := config.Default()
	apiServer := NewServerWithConfig(cfg, store)
	token := bootstrapAndLogin(t, apiServer, cfg)

	orgListReq := httptest.NewRequest(http.MethodGet, "/organizations", nil)
	orgListReq.Header.Set("Authorization", "Bearer "+token)
	orgListRes := httptest.NewRecorder()
	apiServer.Handler().ServeHTTP(orgListRes, orgListReq)
	if orgListRes.Code != http.StatusOK {
		t.Fatalf("expected 200 for organizations list, got %d", orgListRes.Code)
	}
}

func TestCampaignTenantIsolation(t *testing.T) {
	store := storage.NewInMemoryStore()
	cfg := config.Default()
	apiServer := NewServerWithConfig(cfg, store)
	token := bootstrapAndLogin(t, apiServer, cfg)

	_, _ = store.CreateOrganization(storage.Organization{ID: "org-other", Name: "Other Org"})
	campaign, err := core.NewCampaign("cmp-other", "Other Campaign", "https://example.com")
	if err != nil {
		t.Fatalf("failed to create campaign: %v", err)
	}
	_ = store.SaveCampaign(campaign)
	_ = store.SaveCampaignTenant("cmp-other", "org-other")

	findingsReq := httptest.NewRequest(http.MethodGet, "/campaigns/cmp-other/findings", nil)
	findingsReq.Header.Set("Authorization", "Bearer "+token)
	findingsRes := httptest.NewRecorder()
	apiServer.Handler().ServeHTTP(findingsRes, findingsReq)
	if findingsRes.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for cross-tenant campaign access, got %d", findingsRes.Code)
	}
}

func bootstrapAndLogin(t *testing.T, apiServer *Server, cfg config.AppConfig) string {
	t.Helper()
	bootstrapBody := []byte(`{"organization_name":"Acme","admin_email":"admin@acme.test","admin_password":"Secret123!"}`)
	bootstrapReq := httptest.NewRequest(http.MethodPost, "/bootstrap", bytes.NewReader(bootstrapBody))
	bootstrapReq.Header.Set("Content-Type", "application/json")
	bootstrapReq.Header.Set("X-Forge-Bootstrap-Token", cfg.BootstrapToken)
	bootstrapRes := httptest.NewRecorder()
	apiServer.Handler().ServeHTTP(bootstrapRes, bootstrapReq)
	if bootstrapRes.Code != http.StatusCreated {
		t.Fatalf("expected 201 for bootstrap, got %d", bootstrapRes.Code)
	}

	loginBody := []byte(`{"email":"admin@acme.test","password":"Secret123!"}`)
	loginReq := httptest.NewRequest(http.MethodPost, "/auth/login", bytes.NewReader(loginBody))
	loginReq.Header.Set("Content-Type", "application/json")
	loginRes := httptest.NewRecorder()
	apiServer.Handler().ServeHTTP(loginRes, loginReq)
	if loginRes.Code != http.StatusOK {
		t.Fatalf("expected 200 for login, got %d", loginRes.Code)
	}

	var loginPayload map[string]any
	if err := json.Unmarshal(loginRes.Body.Bytes(), &loginPayload); err != nil {
		t.Fatalf("failed to decode login payload: %v", err)
	}
	tokenRaw, ok := loginPayload["token"]
	if !ok {
		t.Fatalf("token missing from login response")
	}
	token, ok := tokenRaw.(string)
	if !ok || token == "" {
		t.Fatalf("invalid token value")
	}
	return token
}
