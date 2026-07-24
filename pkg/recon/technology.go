package recon

import "strings"

// TechnologyProfile captures inferred target stack details.
type TechnologyProfile struct {
	Frontend       string   `json:"frontend"`
	Backend        string   `json:"backend"`
	Database       string   `json:"database"`
	Server         string   `json:"server"`
	CloudProvider  string   `json:"cloud_provider"`
	PotentialRisks []string `json:"potential_risks"`
}

// MergeRisk appends risk if not already present.
func (p *TechnologyProfile) MergeRisk(risk string) {
	risk = strings.TrimSpace(risk)
	if risk == "" {
		return
	}
	for _, existing := range p.PotentialRisks {
		if strings.EqualFold(existing, risk) {
			return
		}
	}
	p.PotentialRisks = append(p.PotentialRisks, risk)
}
