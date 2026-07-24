package evidence

import "testing"

func TestCollectorAddListReset(t *testing.T) {
	collector := NewCollector()
	collector.Add(Artifact{CampaignID: "cmp-1", VulnerabilityName: "SQL Injection"})
	collector.Add(Artifact{CampaignID: "cmp-1", VulnerabilityName: "XSS"})

	items := collector.List()
	if len(items) != 2 {
		t.Fatalf("expected 2 artifacts, got %d", len(items))
	}

	collector.Reset()
	items = collector.List()
	if len(items) != 0 {
		t.Fatalf("expected no artifacts after reset, got %d", len(items))
	}
}
