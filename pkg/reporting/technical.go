package reporting

import (
	"github.com/Jina404/forge/pkg/core"
	"github.com/Jina404/forge/pkg/evidence"
)

// TechnicalReport contains reproducible details for engineers.
type TechnicalReport struct {
	CampaignID      string               `json:"campaign_id"`
	Vulnerabilities []core.Vulnerability `json:"vulnerabilities"`
	Artifacts       []evidence.Artifact  `json:"artifacts"`
	RemediationPlan []string             `json:"remediation_plan"`
}
