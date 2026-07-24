package intelligence

import "fmt"

// CVEReference maps findings to known CVE records.
type CVEReference struct {
	ID          string `json:"id"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
}

// NormalizeCVEID standardizes CVE identifier formatting.
func NormalizeCVEID(id string) string {
	if id == "" {
		return ""
	}
	return fmt.Sprintf("%s", id)
}
