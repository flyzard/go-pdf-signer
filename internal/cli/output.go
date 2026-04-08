package cli

import (
	"encoding/json"
	"fmt"
	"os"
)

type EmbedOutput struct {
	Success bool `json:"success"`
}

type ErrorOutput struct {
	Error   string `json:"error"`
	Message string `json:"message"`
	Detail  string `json:"detail,omitempty"`
}

func PrintJSON(v any) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.Encode(v)
}

func PrintError(code, message string, detail ...string) {
	out := ErrorOutput{Error: code, Message: message}
	if len(detail) > 0 {
		out.Detail = detail[0]
	}
	enc := json.NewEncoder(os.Stderr)
	enc.Encode(out)
	os.Exit(1)
}

func Fatalf(code, format string, args ...any) {
	PrintError(code, fmt.Sprintf(format, args...))
}
