package evidence

import "time"

// Artifact stores reproducible proof for a confirmed vulnerability.
type Artifact struct {
	CampaignID        string    `json:"campaign_id"`
	VulnerabilityName string    `json:"vulnerability_name"`
	Request           string    `json:"request"`
	Response          string    `json:"response"`
	Payload           string    `json:"payload"`
	Timestamp         time.Time `json:"timestamp"`
	Screenshot        string    `json:"screenshot"`
	ReproSteps        []string  `json:"repro_steps"`
}
