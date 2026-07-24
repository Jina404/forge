package reporting

import (
	"encoding/json"
	"fmt"
	"os"
)

// WriteJSON exports report data in JSON format.
func WriteJSON(path string, report any) error {
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

// WriteHTML exports a minimal HTML report.
func WriteHTML(path string, title string, body string) error {
	content := fmt.Sprintf("<html><head><title>%s</title></head><body><h1>%s</h1><pre>%s</pre></body></html>", title, title, body)
	return os.WriteFile(path, []byte(content), 0o644)
}

// WritePDF is intentionally unimplemented until a rendering backend is chosen.
func WritePDF(path string, report any) error {
	_ = path
	_ = report
	return fmt.Errorf("pdf export not implemented yet")
}
