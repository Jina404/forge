package reporting

import "github.com/Jina404/forge/pkg/core"

// ExecutiveReport targets security leadership and business stakeholders.
type ExecutiveReport struct {
	CampaignID       string                `json:"campaign_id"`
	SecurityScore    int                   `json:"security_score"`
	CriticalFindings int                   `json:"critical_findings"`
	TopFindings      []core.Vulnerability  `json:"top_findings"`
	BusinessImpact   []string              `json:"business_impact"`
}
