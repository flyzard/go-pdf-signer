package pdf

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestWriteFileAtomicWritesWithRestrictivePerms(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.pdf")
	content := []byte("hello world")

	if err := WriteFileAtomic(path, content); err != nil {
		t.Fatalf("WriteFileAtomic: %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !bytes.Equal(got, content) {
		t.Errorf("content = %q, want %q", got, content)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	// On Unix, expect exactly 0600; Windows perm semantics differ.
	if runtime.GOOS != "windows" {
		if mode := info.Mode().Perm(); mode != 0o600 {
			t.Errorf("perm = %o, want 0600", mode)
		}
	}
}

func TestWriteFileAtomicReplacesExistingFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.pdf")

	if err := os.WriteFile(path, []byte("old"), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := WriteFileAtomic(path, []byte("new")); err != nil {
		t.Fatalf("WriteFileAtomic: %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(got) != "new" {
		t.Errorf("content = %q, want %q", got, "new")
	}
}

func TestWriteFileAtomicRefusesSymlinkTarget(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink test skipped on windows")
	}
	dir := t.TempDir()
	realTarget := filepath.Join(dir, "real.txt")
	if err := os.WriteFile(realTarget, []byte("precious"), 0o600); err != nil {
		t.Fatalf("seed target: %v", err)
	}

	linkPath := filepath.Join(dir, "link.pdf")
	if err := os.Symlink(realTarget, linkPath); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	err := WriteFileAtomic(linkPath, []byte("malicious"))
	if err == nil {
		t.Fatal("expected error when target is a symlink, got nil")
	}

	// The original file the symlink pointed at must be untouched.
	got, err := os.ReadFile(realTarget)
	if err != nil {
		t.Fatalf("read real target: %v", err)
	}
	if string(got) != "precious" {
		t.Errorf("real target clobbered: got %q", got)
	}
}

func TestWriteFileAtomicDoesNotLeaveTempOnFailure(t *testing.T) {
	// Point at a path whose parent doesn't exist — the CreateTemp call fails
	// and no .tmp file is left behind (in the parent dir, which does exist).
	dir := t.TempDir()
	bogus := filepath.Join(dir, "nonexistent-subdir", "out.pdf")

	if err := WriteFileAtomic(bogus, []byte("x")); err == nil {
		t.Fatal("expected error writing to non-existent parent dir")
	}

	// The temp dir itself should still be empty (no leaked .tmp).
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != 0 {
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("temp dir not empty after failed write: %v", names)
	}
}
