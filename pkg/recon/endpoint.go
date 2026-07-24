package recon

import "regexp"

var endpointPattern = regexp.MustCompile(`https?://[^\s"'<>]+`)

// ExtractEndpoints finds URL-like tokens from text content.
func ExtractEndpoints(content string) []string {
	matches := endpointPattern.FindAllString(content, -1)
	if len(matches) == 0 {
		return []string{}
	}
	out := make([]string, 0, len(matches))
	seen := map[string]struct{}{}
	for _, m := range matches {
		if _, ok := seen[m]; ok {
			continue
		}
		seen[m] = struct{}{}
		out = append(out, m)
	}
	return out
}
