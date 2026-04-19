package detector

import (
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// AdvancedDetector performs blind and context-aware vulnerability detection.
type AdvancedDetector struct {
	baselineResponse []byte // Response body for a normal request (without payload)
	baselineHash     string
	baselineLength   int
}

// NewAdvancedDetector creates a detector with baseline response.
func NewAdvancedDetector() *AdvancedDetector {
	return &AdvancedDetector{}
}

// SetBaseline records the response of a normal request for later comparison.
func (a *AdvancedDetector) SetBaseline(resp *http.Response) {
	if resp == nil {
		return
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body = io.NopCloser(bytes.NewReader(body))
	a.baselineResponse = body
	a.baselineHash = hashBytes(body)
	a.baselineLength = len(body)
}

// BooleanCheck sends two requests with true/false conditions and compares responses.
// Returns true if a boolean-based blind SQLi is detected.
func (a *AdvancedDetector) BooleanCheck(trueResp, falseResp *http.Response) (bool, *Finding) {
	if trueResp == nil || falseResp == nil {
		return false, nil
	}

	trueBody, _ := io.ReadAll(trueResp.Body)
	trueResp.Body = io.NopCloser(bytes.NewReader(trueBody))
	falseBody, _ := io.ReadAll(falseResp.Body)
	falseResp.Body = io.NopCloser(bytes.NewReader(falseBody))

	trueHash := hashBytes(trueBody)
	falseHash := hashBytes(falseBody)

	// Different status codes
	if trueResp.StatusCode != falseResp.StatusCode {
		return true, &Finding{
			Type:       "Boolean-based Blind SQL Injection",
			Evidence:   "Different HTTP status codes: true=" + http.StatusText(trueResp.StatusCode) + ", false=" + http.StatusText(falseResp.StatusCode),
			Confidence: 0.9,
		}
	}

	// Different response length (>5% difference)
	lenDiff := float64(abs(len(trueBody)-len(falseBody))) / float64(max(1, len(trueBody)))
	if lenDiff > 0.05 {
		return true, &Finding{
			Type:       "Boolean-based Blind SQL Injection",
			Evidence:   "Response length differs by >5% between true/false conditions",
			Confidence: 0.85,
		}
	}

	// Different content hash
	if trueHash != falseHash {
		return true, &Finding{
			Type:       "Boolean-based Blind SQL Injection",
			Evidence:   "Response content differs for true/false conditions",
			Confidence: 0.8,
		}
	}

	return false, nil
}

// TimeCheck determines if a response took significantly longer than baseline.
func (a *AdvancedDetector) TimeCheck(baselineLatency, testLatency time.Duration, payload string) (bool, *Finding) {
	// If test latency > baseline + 4 seconds (allowing some network jitter)
	if testLatency > baselineLatency+4*time.Second {
		return true, &Finding{
			Type:       "Time-based Blind SQL Injection",
			Evidence:   "Response delayed by >4 seconds, likely due to SLEEP() or WAITFOR payload",
			Confidence: 0.95,
		}
	}
	return false, nil
}

// DiffAnalysis compares a fuzzed response against the baseline.
func (a *AdvancedDetector) DiffAnalysis(fuzzedResp *http.Response) (bool, *Finding) {
	if a.baselineResponse == nil || fuzzedResp == nil {
		return false, nil
	}

	fuzzBody, _ := io.ReadAll(fuzzedResp.Body)
	fuzzedResp.Body = io.NopCloser(bytes.NewReader(fuzzBody))

	// Detect error messages that weren't in baseline
	errorPatterns := []string{
		"(?i)(sql|syntax|mysql|ora-|postgresql|sqlite|odbc|driver|oledb)",
		"(?i)(warning|error|exception|fatal|stack trace)",
		"(?i)(at line \\d+)",
		"(?i)(on line \\d+)",
		"(?i)(in .+ on line \\d+)",
	}

	for _, pattern := range errorPatterns {
		re := regexp.MustCompile(pattern)
		if re.Match(fuzzBody) && !re.Match(a.baselineResponse) {
			match := re.Find(fuzzBody)
			return true, &Finding{
				Type:       "Error-based Information Disclosure",
				Evidence:   "New error message appeared: " + string(match),
				Confidence: 0.7,
			}
		}
	}

	// Detect new stack traces / file paths
	pathPattern := regexp.MustCompile(`(?i)(/[a-zA-Z0-9_\-\.]+)+\.(php|asp|aspx|jsp|py|rb|go|js)`)
	if pathPattern.Match(fuzzBody) && !pathPattern.Match(a.baselineResponse) {
		match := pathPattern.Find(fuzzBody)
		return true, &Finding{
			Type:       "Path Disclosure",
			Evidence:   "File path leaked: " + string(match),
			Confidence: 0.8,
		}
	}

	return false, nil
}

// ContextAwareXSS analyzes where the payload reflected and suggests impact.
func (a *AdvancedDetector) ContextAwareXSS(body []byte, payload string) *Finding {
	bodyStr := string(body)
	if !strings.Contains(bodyStr, payload) {
		return nil
	}

	// Determine reflection context
	if strings.Contains(bodyStr, "<script>"+payload+"</script>") {
		return &Finding{
			Type:       "Reflected XSS (Script Tag)",
			Evidence:   "Payload reflected inside <script> tags",
			Confidence: 1.0,
		}
	}
	if strings.Contains(bodyStr, "\""+payload+"\"") {
		return &Finding{
			Type:       "Reflected XSS (Double-Quoted Attribute)",
			Evidence:   "Payload reflected inside double-quoted HTML attribute",
			Confidence: 0.9,
		}
	}
	if strings.Contains(bodyStr, "'"+payload+"'") {
		return &Finding{
			Type:       "Reflected XSS (Single-Quoted Attribute)",
			Evidence:   "Payload reflected inside single-quoted HTML attribute",
			Confidence: 0.9,
		}
	}
	if strings.Contains(bodyStr, ">"+payload+"<") {
		return &Finding{
			Type:       "Reflected XSS (Tag Body)",
			Evidence:   "Payload reflected as HTML tag content",
			Confidence: 0.8,
		}
	}
	if strings.Contains(bodyStr, "javascript:"+payload) {
		return &Finding{
			Type:       "Reflected XSS (javascript: URI)",
			Evidence:   "Payload reflected in javascript: context",
			Confidence: 0.95,
		}
	}
	// Generic reflection
	return &Finding{
		Type:       "Reflected XSS (Generic)",
		Evidence:   "Payload reflected in response body",
		Confidence: 0.6,
	}
}

// Helper functions
func hashBytes(b []byte) string {
	h := md5.Sum(b)
	return hex.EncodeToString(h[:])
}

func abs(x int) float64 {
	if x < 0 {
		return float64(-x)
	}
	return float64(x)
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
