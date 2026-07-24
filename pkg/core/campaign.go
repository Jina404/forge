package core

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// CampaignState represents lifecycle status for an assessment campaign.
type CampaignState string

const (
	CampaignCreated   CampaignState = "CREATED"
	CampaignRunning   CampaignState = "RUNNING"
	CampaignPaused    CampaignState = "PAUSED"
	CampaignCompleted CampaignState = "COMPLETED"
	CampaignFailed    CampaignState = "FAILED"
)

// Campaign contains run metadata and lifecycle state.
type Campaign struct {
	ID          string
	Name        string
	TargetURL   string
	State       CampaignState
	CreatedAt   time.Time
	UpdatedAt   time.Time
	StartedAt   *time.Time
	CompletedAt *time.Time
	LastError   string
}

// NewCampaign creates a validated campaign in CREATED state.
func NewCampaign(id, name, targetURL string) (Campaign, error) {
	if strings.TrimSpace(id) == "" {
		return Campaign{}, errors.New("campaign id is required")
	}
	if strings.TrimSpace(name) == "" {
		return Campaign{}, errors.New("campaign name is required")
	}
	if strings.TrimSpace(targetURL) == "" {
		return Campaign{}, errors.New("target URL is required")
	}
	parsed, err := url.ParseRequestURI(targetURL)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return Campaign{}, fmt.Errorf("invalid target URL: %s", targetURL)
	}

	now := time.Now().UTC()
	return Campaign{
		ID:        id,
		Name:      name,
		TargetURL: targetURL,
		State:     CampaignCreated,
		CreatedAt: now,
		UpdatedAt: now,
	}, nil
}

// Transition moves campaign state using a strict lifecycle.
func (c *Campaign) Transition(next CampaignState) error {
	if c == nil {
		return errors.New("campaign is nil")
	}
	if c.State == next {
		return nil
	}

	allowed := map[CampaignState]map[CampaignState]bool{
		CampaignCreated: {
			CampaignRunning: true,
			CampaignFailed:  true,
		},
		CampaignRunning: {
			CampaignPaused:    true,
			CampaignCompleted: true,
			CampaignFailed:    true,
		},
		CampaignPaused: {
			CampaignRunning: true,
			CampaignFailed:  true,
		},
		CampaignCompleted: {},
		CampaignFailed:    {},
	}

	nextAllowed := allowed[c.State]
	if !nextAllowed[next] {
		return fmt.Errorf("invalid campaign transition: %s -> %s", c.State, next)
	}

	now := time.Now().UTC()
	switch next {
	case CampaignRunning:
		if c.StartedAt == nil {
			c.StartedAt = &now
		}
	case CampaignCompleted, CampaignFailed:
		c.CompletedAt = &now
	}

	c.State = next
	c.UpdatedAt = now
	return nil
}
