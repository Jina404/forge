package engine

import (
	"net/http"
	"strings"
	"time"

	"github.com/Jina404/forge/pkg/detector"
	"github.com/Jina404/forge/pkg/fuzzer"
	"github.com/Jina404/forge/pkg/metrics"
)

type FuzzWorkerConfig struct {
	TargetURL       string
	Method          string
	FuzzParam       string
	Headers         map[string]string
	Timeout         time.Duration
	Metrics         *metrics.Collector
	StopChannel     <-chan struct{}
	Fuzzer          *fuzzer.Fuzzer
	Detector        *detector.Detector
	BaselineLatency time.Duration // Average latency of normal requests
}

func RunFuzzWorker(cfg FuzzWorkerConfig) {
	client := NewOptimizedClient(cfg.Timeout)
	urlTemplate := cfg.TargetURL + cfg.FuzzParam

	for {
		select {
		case <-cfg.StopChannel:
			return
		default:
			fuzzedURL := cfg.Fuzzer.Mutate(urlTemplate)
			payload := extractPayload(fuzzedURL)

			req, err := http.NewRequest(cfg.Method, fuzzedURL, nil)
			if err != nil {
				continue
			}
			for k, v := range cfg.Headers {
				req.Header.Set(k, v)
			}
			req.Header.Set("X-Forge-Fuzz", "1")

			start := time.Now()
			resp, err := client.Do(req)
			latency := time.Since(start)

			success := err == nil && resp != nil
			cfg.Metrics.Record(success, latency)

			if resp != nil {
				if cfg.Detector != nil {
					cfg.Detector.Analyze(resp, payload, fuzzedURL, latency, cfg.BaselineLatency)
				}
				DrainBody(resp)
			}
		}
	}
}

func extractPayload(fullURL string) string {
	if idx := strings.LastIndex(fullURL, "="); idx != -1 {
		return fullURL[idx+1:]
	}
	return fullURL
}
