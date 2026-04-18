package pades

import (
	"testing"

	"github.com/flyzard/pdf-signer/internal/pdf"
)

// TestWalkFieldTreeAcceptsInlineDicts verifies that a /Fields entry that is
// an inline pdf.Dict (rather than an indirect pdf.Ref) still reaches the
// visit callback. Some PDF producers use inline dicts for small form trees.
func TestWalkFieldTreeAcceptsInlineDicts(t *testing.T) {
	inlineField := pdf.Dict{
		"T":  "InlineSig",
		"FT": pdf.Name("Sig"),
	}
	fields := []any{inlineField}

	var visited []pdf.Dict
	walkFieldTree(&pdf.Document{}, fields, func(d pdf.Dict) {
		visited = append(visited, d)
	})

	if len(visited) != 1 {
		t.Fatalf("visited %d fields, want 1", len(visited))
	}
	if got, _ := visited[0].GetName("FT"); got != "Sig" {
		t.Errorf("visited dict FT=%q, want Sig", got)
	}
}

// TestWalkFieldTreeInlineKids verifies recursion through an inline dict's
// /Kids array.
func TestWalkFieldTreeInlineKids(t *testing.T) {
	leaf := pdf.Dict{"T": "Leaf", "FT": pdf.Name("Sig")}
	parent := pdf.Dict{
		"T":    "Parent",
		"Kids": []any{leaf},
	}
	fields := []any{parent}

	var visited []pdf.Dict
	walkFieldTree(&pdf.Document{}, fields, func(d pdf.Dict) {
		visited = append(visited, d)
	})

	if len(visited) != 1 {
		t.Fatalf("visited %d fields, want 1 (leaf only)", len(visited))
	}
	got, _ := visited[0]["T"].(string)
	if got != "Leaf" {
		t.Errorf("visited /T = %q, want %q", got, "Leaf")
	}
}
