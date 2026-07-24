package core

import (
	"testing"
	"time"

	"github.com/Jina404/forge/pkg/detector"
	"github.com/Jina404/forge/pkg/engine"
	"github.com/Jina404/forge/pkg/evidence"
	"github.com/Jina404/forge/pkg/metrics"
)

type fakeRunner struct {
	snapshot metrics.Snapshot
	findings []detector.Finding
}

func (f *fakeRunner) Start() {}
func (f *fakeRunner) Wait() {}
func (f *fakeRunner) Metrics() metrics.Snapshot { return f.snapshot }
func (f *fakeRunner) Findings() []detector.Finding { return f.findings }

type fakeCampaignStore struct {
	campaign Campaign
}

func (s *fakeCampaignStore) SaveCampaign(c Campaign) error { s.campaign = c; return nil }
func (s *fakeCampaignStore) GetCampaign(id string) (Campaign, error) { return s.campaign, nil }

type fakeVulnerabilityStore struct {
	items []Vulnerability
}

func (s *fakeVulnerabilityStore) SaveVulnerability(campaignID string, vulnerability Vulnerability) error {
	s.items = append(s.items, vulnerability)
	return nil
}
func (s *fakeVulnerabilityStore) ListVulnerabilities(campaignID string) ([]Vulnerability, error) { return s.items, nil }

type fakeEvidenceStore struct {
	items []evidence.Artifact
}

func (s *fakeEvidenceStore) SaveArtifact(campaignID string, artifact evidence.Artifact) error {
	s.items = append(s.items, artifact)
	return nil
}
func (s *fakeEvidenceStore) ListArtifacts(campaignID string) ([]evidence.Artifact, error) { return s.items, nil }

func TestOrchestratorExecuteCampaign(t *testing.T) {
	campaign, err := NewCampaign("cmp-1", "Campaign", "https://example.com")
	if err != nil {
		t.Fatalf("unexpected campaign error: %v", err)
	}

	runner := &fakeRunner{
		snapshot: metrics.Snapshot{TotalRequests: 100, SuccessRequests: 95},
		findings: []detector.Finding{{
			Type:       "SQL Injection (Error-based)",
			Payload:    "' OR '1'='1",
			URL:        "https://example.com/search?q=' OR '1'='1",
			Evidence:   "SQL syntax",
			StatusCode: 500,
			Confidence: 0.95,
			Timestamp:  time.Now().UTC(),
		}},
	}

	campaignStore := &fakeCampaignStore{}
	vulnStore := &fakeVulnerabilityStore{}
	evidenceStore := &fakeEvidenceStore{}
	collector := evidence.NewCollector()

	orchestrator, err := NewOrchestrator(
		func(cfg engine.Config) (EngineRunner, error) { return runner, nil },
		campaignStore,
		vulnStore,
		evidenceStore,
		collector,
		DefaultWorkflow(),
	)
	if err != nil {
		t.Fatalf("unexpected orchestrator error: %v", err)
	}

	result, err := orchestrator.ExecuteCampaign(campaign, engine.Config{Method: "GET"})
	if err != nil {
		t.Fatalf("unexpected execute error: %v", err)
	}

	if result.Campaign.State != CampaignCompleted {
		t.Fatalf("expected campaign state COMPLETED, got %s", result.Campaign.State)
	}
	if len(result.Vulnerabilities) != 1 {
		t.Fatalf("expected 1 vulnerability, got %d", len(result.Vulnerabilities))
	}
	if len(result.Artifacts) != 1 {
		t.Fatalf("expected 1 artifact, got %d", len(result.Artifacts))
	}
}
