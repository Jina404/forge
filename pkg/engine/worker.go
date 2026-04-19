package engine

import (
	"context"
	"log"
	"net/http"
	"time"

	"github.com/Jina404/forge/pkg/metrics"
)

type WorkerConfig struct {
	TargetURL   string
	Method      string
	Headers     map[string]string
	Timeout     time.Duration
	Metrics     *metrics.Collector
	StopChannel <-chan struct{}
}

func RunWorker(cfg WorkerConfig) {
	client := NewOptimizedClient(cfg.Timeout)

	req, err := http.NewRequest(cfg.Method, cfg.TargetURL, nil)
	if err != nil {
		log.Printf("Worker failed to create request: %v", err)
		return
	}
	for k, v := range cfg.Headers {
		req.Header.Set(k, v)
	}

	for {
		select {
		case <-cfg.StopChannel:
			return
		default:
			reqClone := req.Clone(context.Background())
			start := time.Now()
			resp, err := client.Do(reqClone)
			latency := time.Since(start)

			success := err == nil && resp != nil && resp.StatusCode < 500
			cfg.Metrics.Record(success, latency)

			if resp != nil {
				DrainBody(resp)
			}
		}
	}
}
