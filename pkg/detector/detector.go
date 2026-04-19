package detector

import (
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Finding represents a potential vulnerability.
type Finding struct {
	Type       string    `json:"type"`
	Payload    string    `json:"payload"`
	URL        string    `json:"url"`
	Evidence   string    `json:"evidence"`
	StatusCode int       `json:"status_code"`
	Confidence float64   `json:"confidence"` // 0.0 to 1.0
	Timestamp  time.Time `json:"timestamp"`
}

// Detector holds signature rules and findings.
type Detector struct {
	findings   []Finding
	mu         sync.Mutex
	advanced   *AdvancedDetector
	baseline   *http.Response // baseline response for diffing
}

// NewDetector creates a new detector with built-in rules.
func NewDetector() *Detector {
	return &Detector{
		findings: make([]Finding, 0),
		advanced: NewAdvancedDetector(),
	}
}

// SetBaselineResponse records a normal response for diffing.
func (d *Detector) SetBaselineResponse(resp *http.Response) {
	d.baseline = resp
	d.advanced.SetBaseline(resp)
}

// Analyze examines an HTTP response for vulnerability signatures.
func (d *Detector) Analyze(resp *http.Response, payload, fullURL string, latency time.Duration, baselineLatency time.Duration) bool {
	if resp == nil {
		return false
	}

	// Read body for analysis (up to 500KB)
	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 500*1024))
	if err != nil {
		return false
	}
	resp.Body = io.NopCloser(strings.NewReader(string(bodyBytes)))
	body := string(bodyBytes)

	var findings []*Finding

	// 1. Signature-based SQLi
	if f := d.checkSQLi(body, payload, fullURL, resp.StatusCode); f != nil {
		findings = append(findings, f)
	}

	// 2. Context-aware XSS
	if f := d.advanced.ContextAwareXSS(bodyBytes, payload); f != nil {
		f.Payload = payload
		f.URL = fullURL
		f.StatusCode = resp.StatusCode
		f.Timestamp = time.Now()
		findings = append(findings, f)
	}

	// 3. Path Traversal
	if f := d.checkPathTraversal(body, payload, fullURL, resp.StatusCode); f != nil {
		findings = append(findings, f)
	}

	// 4. Command Injection
	if f := d.checkCommandInjection(body, payload, fullURL, resp.StatusCode); f != nil {
		findings = append(findings, f)
	}

	// 5. JNDI
	if f := d.checkJNDI(body, payload, fullURL, resp.StatusCode); f != nil {
		findings = append(findings, f)
	}

	// 6. Time-based detection
	if baselineLatency > 0 {
		if detected, f := d.advanced.TimeCheck(baselineLatency, latency, payload); detected {
			f.Payload = payload
			f.URL = fullURL
			f.StatusCode = resp.StatusCode
			f.Timestamp = time.Now()
			findings = append(findings, f)
		}
	}

	// 7. Diff analysis against baseline
	if d.baseline != nil {
		if detected, f := d.advanced.DiffAnalysis(resp); detected {
			f.Payload = payload
			f.URL = fullURL
			f.StatusCode = resp.StatusCode
			f.Timestamp = time.Now()
			findings = append(findings, f)
		}
	}

	if len(findings) > 0 {
		d.mu.Lock()
		for _, f := range findings {
			d.findings = append(d.findings, *f)
		}
		d.mu.Unlock()
		return true
	}
	return false
}

// checkSQLi performs signature-based SQL injection detection.
func (d *Detector) checkSQLi(body, payload, url string, status int) *Finding {
	patterns := []string{
		"SQL syntax",
		"mysql_fetch",
		"ORA-\\d+",
		"PostgreSQL",
		"SQLite",
		"Unclosed quotation mark",
		"Microsoft OLE DB",
		"ODBC Driver",
		"SQL command not properly ended",
		"Warning.*mysql_",
		"valid MySQL result",
		"PostgreSQL.*ERROR",
		"SQLite.*Error",
	}
	for _, p := range patterns {
		if matched, _ := regexp.MatchString("(?i)"+p, body); matched {
			re := regexp.MustCompile("(?i)" + p)
			match := re.FindString(body)
			return &Finding{
				Type:       "SQL Injection (Error-based)",
				Payload:    payload,
				URL:        url,
				Evidence:   match,
				StatusCode: status,
				Confidence: 0.9,
				Timestamp:  time.Now(),
			}
		}
	}
	return nil
}

func (d *Detector) checkPathTraversal(body, payload, url string, status int) *Finding {
	patterns := []string{
		"root:.*:0:",
		"daemon:.*:1:",
		"bin:.*:2:",
		"\\[extensions\\]",
		"boot loader",
		"\\[boot loader\\]",
	}
	for _, p := range patterns {
		if matched, _ := regexp.MatchString("(?i)"+p, body); matched {
			return &Finding{
				Type:       "Path Traversal",
				Payload:    payload,
				URL:        url,
				Evidence:   "Sensitive file content leaked",
				StatusCode: status,
				Confidence: 0.85,
				Timestamp:  time.Now(),
			}
		}
	}
	return nil
}

func (d *Detector) checkCommandInjection(body, payload, url string, status int) *Finding {
	patterns := []string{
		"uid=\\d+",
		"gid=\\d+",
		"groups=\\d+",
		"total \\d+",
		"Directory of ",
		"Volume in drive",
	}
	for _, p := range patterns {
		if matched, _ := regexp.MatchString("(?i)"+p, body); matched {
			return &Finding{
				Type:       "Command Injection",
				Payload:    payload,
				URL:        url,
				Evidence:   "Command output reflected",
				StatusCode: status,
				Confidence: 0.8,
				Timestamp:  time.Now(),
			}
		}
	}
	return nil
}

func (d *Detector) checkJNDI(body, payload, url string, status int) *Finding {
	if strings.Contains(strings.ToLower(body), "jndi") ||
		strings.Contains(strings.ToLower(body), "ldap") ||
		strings.Contains(strings.ToLower(body), "namingexception") {
		return &Finding{
			Type:       "JNDI Injection (Log4Shell)",
			Payload:    payload,
			URL:        url,
			Evidence:   "JNDI reference in response",
			StatusCode: status,
			Confidence: 0.7,
			Timestamp:  time.Now(),
		}
	}
	return nil
}

// GetFindings returns all findings.
func (d *Detector) GetFindings() []Finding {
	d.mu.Lock()
	defer d.mu.Unlock()
	results := make([]Finding, len(d.findings))
	copy(results, d.findings)
	return results
}

// ClearFindings resets findings.
func (d *Detector) ClearFindings() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.findings = make([]Finding, 0)
}
