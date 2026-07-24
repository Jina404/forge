package core

import "testing"

func TestCampaignTransitions(t *testing.T) {
	campaign, err := NewCampaign("cmp-1", "API Assessment", "https://example.com")
	if err != nil {
		t.Fatalf("unexpected create error: %v", err)
	}

	if err := campaign.Transition(CampaignRunning); err != nil {
		t.Fatalf("expected CREATED -> RUNNING to be valid: %v", err)
	}
	if err := campaign.Transition(CampaignPaused); err != nil {
		t.Fatalf("expected RUNNING -> PAUSED to be valid: %v", err)
	}
	if err := campaign.Transition(CampaignRunning); err != nil {
		t.Fatalf("expected PAUSED -> RUNNING to be valid: %v", err)
	}
	if err := campaign.Transition(CampaignCompleted); err != nil {
		t.Fatalf("expected RUNNING -> COMPLETED to be valid: %v", err)
	}

	if err := campaign.Transition(CampaignRunning); err == nil {
		t.Fatalf("expected COMPLETED -> RUNNING to be invalid")
	}
}

func TestNewCampaignValidation(t *testing.T) {
	if _, err := NewCampaign("", "x", "https://example.com"); err == nil {
		t.Fatalf("expected missing id validation error")
	}
	if _, err := NewCampaign("id", "", "https://example.com"); err == nil {
		t.Fatalf("expected missing name validation error")
	}
	if _, err := NewCampaign("id", "name", "not-a-url"); err == nil {
		t.Fatalf("expected invalid URL validation error")
	}
}
