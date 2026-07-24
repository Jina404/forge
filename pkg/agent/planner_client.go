package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/Jina404/forge/pkg/core"
)

// PlannerClient calls the Python AI planner service over HTTP.
type PlannerClient struct {
	baseURL string
	client  *http.Client
}

func NewPlannerClient(baseURL string, timeout time.Duration) *PlannerClient {
	return &PlannerClient{
		baseURL: strings.TrimRight(baseURL, "/"),
		client:  &http.Client{Timeout: timeout},
	}
}

func (c *PlannerClient) Plan(ctx context.Context, campaign core.Campaign) (core.PlanResult, error) {
	requestBody := map[string]string{
		"target":      campaign.TargetURL,
		"campaign_id": campaign.ID,
		"goal":        campaign.Name,
	}
	data, err := json.Marshal(requestBody)
	if err != nil {
		return core.PlanResult{}, err
	}

	endpoint := c.baseURL + "/plan"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(data))
	if err != nil {
		return core.PlanResult{}, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return core.PlanResult{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		return core.PlanResult{}, fmt.Errorf("planner returned status %d", resp.StatusCode)
	}

	var result core.PlanResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return core.PlanResult{}, err
	}
	return result, nil
}
