package evidence

import "sync"

// Collector tracks evidence artifacts in-memory during execution.
type Collector struct {
	mu        sync.Mutex
	artifacts []Artifact
}

func NewCollector() *Collector {
	return &Collector{artifacts: make([]Artifact, 0)}
}

// Add stores a single artifact.
func (c *Collector) Add(artifact Artifact) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.artifacts = append(c.artifacts, artifact)
}

// List returns a copy of all collected artifacts.
func (c *Collector) List() []Artifact {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]Artifact, len(c.artifacts))
	copy(out, c.artifacts)
	return out
}

// Reset clears all artifacts.
func (c *Collector) Reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.artifacts = make([]Artifact, 0)
}
