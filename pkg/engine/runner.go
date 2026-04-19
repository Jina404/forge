package engine

import (
	"net/http"
	"sync"
	"time"

	"github.com/Jina404/forge/pkg/detector"
	"github.com/Jina404/forge/pkg/fuzzer"
	"github.com/Jina404/forge/pkg/metrics"
)

type Runner struct {
	Config         Config
	metrics        *metrics.Collector
	detector       *detector.Detector
	stopChan       chan struct{}
	workerWg       sync.WaitGroup
	workers        int
	mu             sync.Mutex
	running        bool
	fuzzer         *fuzzer.Fuzzer
	baselineLatency time.Duration
}

type Config struct {
	TargetURL     string
	Method        string
	Concurrency   int
	Duration      time.Duration
	Timeout       time.Duration
	Headers       map[string]string
	FuzzRatio     float64
	FuzzParam     string
	PayloadFile   string
	EstablishBaseline bool // New: capture normal response for diffing
}

func NewRunner(cfg Config) (*Runner, error) {
	var f *fuzzer.Fuzzer
	var err error
	var d *detector.Detector

	if cfg.FuzzRatio > 0 && cfg.FuzzParam != "" {
		f, err = fuzzer.NewFuzzer(cfg.PayloadFile)
		if err != nil {
			return nil, err
		}
		d = detector.NewDetector()
	}

	r := &Runner{
		Config:   cfg,
		metrics:  metrics.NewCollector(),
		detector: d,
		stopChan: make(chan struct{}),
		workers:  cfg.Concurrency,
		fuzzer:   f,
	}

	// Establish baseline if requested
	if cfg.EstablishBaseline && d != nil {
		r.captureBaseline()
	}

	return r, nil
}

func (r *Runner) captureBaseline() {
	client := NewOptimizedClient(r.Config.Timeout)
	req, _ := http.NewRequest(r.Config.Method, r.Config.TargetURL, nil)
	for k, v := range r.Config.Headers {
		req.Header.Set(k, v)
	}
	start := time.Now()
	resp, err := client.Do(req)
	if err == nil && resp != nil {
		r.baselineLatency = time.Since(start)
		r.detector.SetBaselineResponse(resp)
		DrainBody(resp)
	}
}

func (r *Runner) Start() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.running {
		return
	}
	r.running = true

	fuzzWorkers := int(float64(r.workers) * r.Config.FuzzRatio)
	normalWorkers := r.workers - fuzzWorkers

	// Normal workers
	for i := 0; i < normalWorkers; i++ {
		r.workerWg.Add(1)
		go func() {
			defer r.workerWg.Done()
			RunWorker(WorkerConfig{
				TargetURL:   r.Config.TargetURL,
				Method:      r.Config.Method,
				Headers:     r.Config.Headers,
				Timeout:     r.Config.Timeout,
				Metrics:     r.metrics,
				StopChannel: r.stopChan,
			})
		}()
	}

	// Fuzzing workers
	if r.fuzzer != nil && fuzzWorkers > 0 {
		for i := 0; i < fuzzWorkers; i++ {
			r.workerWg.Add(1)
			go func() {
				defer r.workerWg.Done()
				RunFuzzWorker(FuzzWorkerConfig{
					TargetURL:       r.Config.TargetURL,
					Method:          r.Config.Method,
					FuzzParam:       r.Config.FuzzParam,
					Headers:         r.Config.Headers,
					Timeout:         r.Config.Timeout,
					Metrics:         r.metrics,
					StopChannel:     r.stopChan,
					Fuzzer:          r.fuzzer,
					Detector:        r.detector,
					BaselineLatency: r.baselineLatency,
				})
			}()
		}
	}

	go func() {
		time.Sleep(r.Config.Duration)
		r.Stop()
	}()
}

func (r *Runner) Stop() {
	r.mu.Lock()
	if !r.running {
		r.mu.Unlock()
		return
	}
	r.running = false
	r.mu.Unlock()

	close(r.stopChan)
	r.workerWg.Wait()
}

func (r *Runner) Wait() {
	r.workerWg.Wait()
}

func (r *Runner) Metrics() metrics.Snapshot {
	return r.metrics.Snapshot()
}

func (r *Runner) Findings() []detector.Finding {
	if r.detector == nil {
		return nil
	}
	return r.detector.GetFindings()
}
