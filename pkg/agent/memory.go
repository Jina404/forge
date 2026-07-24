package agent

import "sync"

// Memory keeps action history keyed by campaign ID.
type Memory struct {
	mu      sync.RWMutex
	actions map[string][]Action
}

func NewMemory() *Memory {
	return &Memory{actions: make(map[string][]Action)}
}

func (m *Memory) Append(campaignID string, action Action) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.actions[campaignID] = append(m.actions[campaignID], action)
	return nil
}

func (m *Memory) List(campaignID string) []Action {
	m.mu.RLock()
	defer m.mu.RUnlock()
	items := m.actions[campaignID]
	out := make([]Action, len(items))
	copy(out, items)
	return out
}
