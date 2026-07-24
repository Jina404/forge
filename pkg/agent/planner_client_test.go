package agent

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Jina404/forge/pkg/core"
)

func TestPlannerClientPlan(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/plan" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"target":"https://example.com","steps":[{"name":"recon","description":"discover"}]}`))
	}))
	defer server.Close()

	client := NewPlannerClient(server.URL, 2*time.Second)
	campaign := core.Campaign{ID: "cmp-1", Name: "Assessment", TargetURL: "https://example.com"}

	result, err := client.Plan(context.Background(), campaign)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Target != "https://example.com" {
		t.Fatalf("unexpected target: %s", result.Target)
	}
	if len(result.Steps) != 1 {
		t.Fatalf("expected one step, got %d", len(result.Steps))
	}
}
