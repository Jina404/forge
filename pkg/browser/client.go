package browser

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// Client communicates with the Playwright browser service.
type Client struct {
	baseURL string
	client  *http.Client
}

func NewClient(baseURL string, timeout time.Duration) *Client {
	return &Client{
		baseURL: strings.TrimRight(baseURL, "/"),
		client:  &http.Client{Timeout: timeout},
	}
}

// Capture requests a screenshot and returns the stored artifact path.
func (c *Client) Capture(ctx context.Context, campaignID string, targetURL string, findingType string) (string, error) {
	if c.baseURL == "" {
		return "", fmt.Errorf("browser service URL is empty")
	}
	requestBody := map[string]string{
		"campaign_id": campaignID,
		"target_url":  targetURL,
		"finding_type": findingType,
	}
	data, err := json.Marshal(requestBody)
	if err != nil {
		return "", err
	}

	endpoint := c.baseURL + "/capture"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(data))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		return "", fmt.Errorf("browser service returned status %d", resp.StatusCode)
	}

	var response struct {
		Path string `json:"path"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return "", err
	}
	if response.Path == "" {
		return "", fmt.Errorf("browser service returned empty path")
	}
	return response.Path, nil
}
