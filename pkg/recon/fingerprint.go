package recon

import (
	"net/http"
	"strings"
)

// Fingerprinter detects technologies from response headers.
type Fingerprinter struct{}

func NewFingerprinter() *Fingerprinter { return &Fingerprinter{} }

func (f *Fingerprinter) FromHeaders(headers http.Header) TechnologyProfile {
	profile := TechnologyProfile{}
	server := headers.Get("Server")
	poweredBy := headers.Get("X-Powered-By")

	profile.Server = server
	if strings.Contains(strings.ToLower(poweredBy), "express") {
		profile.Backend = "Node.js"
	}
	if strings.Contains(strings.ToLower(poweredBy), "php") {
		profile.Backend = "PHP"
	}
	if strings.Contains(strings.ToLower(server), "cloudflare") {
		profile.CloudProvider = "Cloudflare"
		profile.MergeRisk("WAF behavior can mask backend errors")
	}
	if headers.Get("Set-Cookie") != "" {
		profile.MergeRisk("Session management should be validated")
	}

	return profile
}
