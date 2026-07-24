package core

import (
	"context"
	"fmt"
	"time"

	"github.com/Jina404/forge/pkg/detector"
	"github.com/Jina404/forge/pkg/engine"
	"github.com/Jina404/forge/pkg/evidence"
	"github.com/Jina404/forge/pkg/metrics"
)

// Vulnerability is the normalized finding shape used by campaigns and reporting.
type Vulnerability struct {
	Title       string  `json:"title"`
	Severity    string  `json:"severity"`
	Confidence  float64 `json:"confidence"`
	Evidence    string  `json:"evidence"`
	Impact      string  `json:"impact"`
	Remediation string  `json:"remediation"`
}

// EngineRunner captures the behavior required from the current load/fuzz engine.
type EngineRunner interface {
	Start()
	Wait()
	Metrics() metrics.Snapshot
	Findings() []detector.Finding
}

// CampaignStore persists campaign lifecycle state.
type CampaignStore interface {
	SaveCampaign(campaign Campaign) error
	GetCampaign(id string) (Campaign, error)
}

// VulnerabilityStore persists normalized vulnerabilities.
type VulnerabilityStore interface {
	SaveVulnerability(campaignID string, vulnerability Vulnerability) error
	ListVulnerabilities(campaignID string) ([]Vulnerability, error)
}

// EvidenceStore persists evidence artifacts.
type EvidenceStore interface {
	SaveArtifact(campaignID string, artifact evidence.Artifact) error
	ListArtifacts(campaignID string) ([]evidence.Artifact, error)
}

// PlannerService requests an attack plan from an external AI planner.
type PlannerService interface {
	Plan(ctx context.Context, campaign Campaign) (PlanResult, error)
}

// ScreenshotService captures screenshot evidence for findings.
type ScreenshotService interface {
	Capture(ctx context.Context, campaignID string, targetURL string, findingType string) (string, error)
}

// PlanResult is a minimal planner output shape for orchestration and API use.
type PlanResult struct {
	Target string     `json:"target"`
	Steps  []PlanStep `json:"steps"`
}

// PlanStep is one AI-produced action item in an attack plan.
type PlanStep struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

// NewRunnerFunc allows dependency injection for tests.
type NewRunnerFunc func(cfg engine.Config) (EngineRunner, error)

// Orchestrator coordinates campaign execution over the existing Forge engine.
type Orchestrator struct {
	newRunner          NewRunnerFunc
	campaignStore      CampaignStore
	vulnerabilityStore VulnerabilityStore
	evidenceStore      EvidenceStore
	collector          *evidence.Collector
	workflow           Workflow
	planner            PlannerService
	screenshotter      ScreenshotService
}

// OrchestratorOption allows optional integrations without breaking existing constructor usage.
type OrchestratorOption func(*Orchestrator)

// WithPlanner registers an external AI planner service.
func WithPlanner(planner PlannerService) OrchestratorOption {
	return func(o *Orchestrator) {
		o.planner = planner
	}
}

// WithScreenshotter registers an external screenshot capture service.
func WithScreenshotter(s ScreenshotService) OrchestratorOption {
	return func(o *Orchestrator) {
		o.screenshotter = s
	}
}

// RunResult is the output of one campaign execution.
type RunResult struct {
	Campaign        Campaign
	Metrics         metrics.Snapshot
	Vulnerabilities []Vulnerability
	Artifacts       []evidence.Artifact
}

func NewOrchestrator(
	newRunner NewRunnerFunc,
	campaignStore CampaignStore,
	vulnerabilityStore VulnerabilityStore,
	evidenceStore EvidenceStore,
	collector *evidence.Collector,
	workflow Workflow,
	options ...OrchestratorOption,
) (*Orchestrator, error) {
	if newRunner == nil {
		return nil, fmt.Errorf("new runner function is required")
	}
	if campaignStore == nil || vulnerabilityStore == nil || evidenceStore == nil {
		return nil, fmt.Errorf("all stores are required")
	}
	if collector == nil {
		return nil, fmt.Errorf("evidence collector is required")
	}
	if err := workflow.Validate(); err != nil {
		return nil, err
	}
	o := &Orchestrator{
		newRunner:          newRunner,
		campaignStore:      campaignStore,
		vulnerabilityStore: vulnerabilityStore,
		evidenceStore:      evidenceStore,
		collector:          collector,
		workflow:           workflow,
	}
	for _, option := range options {
		if option != nil {
			option(o)
		}
	}
	return o, nil
}

// ExecuteCampaign runs a single campaign using the existing high-concurrency engine.
func (o *Orchestrator) ExecuteCampaign(campaign Campaign, cfg engine.Config) (RunResult, error) {
	ctx := context.Background()

	if err := campaign.Transition(CampaignRunning); err != nil {
		return RunResult{}, err
	}
	if err := o.campaignStore.SaveCampaign(campaign); err != nil {
		return RunResult{}, err
	}

	if o.planner != nil {
		_, err := o.planner.Plan(ctx, campaign)
		if err != nil {
			return RunResult{}, err
		}
	}

	runner, err := o.newRunner(cfg)
	if err != nil {
		_ = campaign.Transition(CampaignFailed)
		campaign.LastError = err.Error()
		_ = o.campaignStore.SaveCampaign(campaign)
		return RunResult{}, err
	}

	runner.Start()
	runner.Wait()

	findings := runner.Findings()
	vulnerabilities := make([]Vulnerability, 0, len(findings))
	for _, finding := range findings {
		vulnerability := mapFindingToVulnerability(finding)
		vulnerabilities = append(vulnerabilities, vulnerability)
		if err := o.vulnerabilityStore.SaveVulnerability(campaign.ID, vulnerability); err != nil {
			return RunResult{}, err
		}

		artifact := evidence.Artifact{
			CampaignID:        campaign.ID,
			VulnerabilityName: vulnerability.Title,
			Request:           fmt.Sprintf("%s %s", cfg.Method, finding.URL),
			Response:          fmt.Sprintf("status=%d evidence=%s", finding.StatusCode, finding.Evidence),
			Payload:           finding.Payload,
			Timestamp:         time.Now().UTC(),
			Screenshot:        "",
			ReproSteps: []string{
				"Replay the request with the recorded payload.",
				"Observe the response evidence and status code.",
				"Confirm the behavior persists across at least two attempts.",
			},
		}
		if o.screenshotter != nil {
			screenshotPath, err := o.screenshotter.Capture(ctx, campaign.ID, finding.URL, finding.Type)
			if err == nil {
				artifact.Screenshot = screenshotPath
			}
		}
		o.collector.Add(artifact)
		if err := o.evidenceStore.SaveArtifact(campaign.ID, artifact); err != nil {
			return RunResult{}, err
		}
	}

	if err := campaign.Transition(CampaignCompleted); err != nil {
		return RunResult{}, err
	}
	if err := o.campaignStore.SaveCampaign(campaign); err != nil {
		return RunResult{}, err
	}

	return RunResult{
		Campaign:        campaign,
		Metrics:         runner.Metrics(),
		Vulnerabilities: vulnerabilities,
		Artifacts:       o.collector.List(),
	}, nil
}

func mapFindingToVulnerability(finding detector.Finding) Vulnerability {
	explanation := detector.Explain(finding)
	severity := "medium"
	switch {
	case finding.Confidence >= 0.9:
		severity = "critical"
	case finding.Confidence >= 0.75:
		severity = "high"
	case finding.Confidence >= 0.5:
		severity = "medium"
	default:
		severity = "low"
	}

	return Vulnerability{
		Title:       finding.Type,
		Severity:    severity,
		Confidence:  finding.Confidence,
		Evidence:    finding.Evidence,
		Impact:      explanation.Impact,
		Remediation: explanation.Remediation,
	}
}
