package metrics

import (
	"sync/atomic"
	"time"
)

type Collector struct {
	TotalRequests   uint64
	SuccessRequests uint64
	ErrorRequests   uint64
	TotalLatencyNs  uint64
	MinLatencyNs    uint64
	MaxLatencyNs    uint64
	Buckets         [20]uint64
}

func NewCollector() *Collector {
	return &Collector{
		MinLatencyNs: ^uint64(0),
	}
}

func (c *Collector) Record(success bool, latency time.Duration) {
	atomic.AddUint64(&c.TotalRequests, 1)
	if success {
		atomic.AddUint64(&c.SuccessRequests, 1)
	} else {
		atomic.AddUint64(&c.ErrorRequests, 1)
	}

	latencyNs := uint64(latency.Nanoseconds())
	atomic.AddUint64(&c.TotalLatencyNs, latencyNs)

	for {
		oldMin := atomic.LoadUint64(&c.MinLatencyNs)
		if latencyNs >= oldMin {
			break
		}
		if atomic.CompareAndSwapUint64(&c.MinLatencyNs, oldMin, latencyNs) {
			break
		}
	}
	for {
		oldMax := atomic.LoadUint64(&c.MaxLatencyNs)
		if latencyNs <= oldMax {
			break
		}
		if atomic.CompareAndSwapUint64(&c.MaxLatencyNs, oldMax, latencyNs) {
			break
		}
	}
}

func (c *Collector) Snapshot() Snapshot {
	return Snapshot{
		TotalRequests:   atomic.LoadUint64(&c.TotalRequests),
		SuccessRequests: atomic.LoadUint64(&c.SuccessRequests),
		ErrorRequests:   atomic.LoadUint64(&c.ErrorRequests),
		AvgLatencyMs:    c.avgLatencyMs(),
		MinLatencyMs:    float64(atomic.LoadUint64(&c.MinLatencyNs)) / 1e6,
		MaxLatencyMs:    float64(atomic.LoadUint64(&c.MaxLatencyNs)) / 1e6,
	}
}

func (c *Collector) avgLatencyMs() float64 {
	total := atomic.LoadUint64(&c.TotalRequests)
	if total == 0 {
		return 0
	}
	sum := atomic.LoadUint64(&c.TotalLatencyNs)
	return float64(sum) / float64(total) / 1e6
}

type Snapshot struct {
	TotalRequests   uint64
	SuccessRequests uint64
	ErrorRequests   uint64
	AvgLatencyMs    float64
	MinLatencyMs    float64
	MaxLatencyMs    float64
}
