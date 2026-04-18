package pdf

import (
	"fmt"
	"os"
	"path/filepath"
)

// WriteFileAtomic writes data to path with the default 0600 permissions
// (inherited from os.CreateTemp). Callers that need explicit perms must
// use WriteFileAtomicMode.
func WriteFileAtomic(path string, data []byte) error {
	return WriteFileAtomicMode(path, data, 0)
}

// WriteFileAtomicMode is like WriteFileAtomic but also chmods the temp
// file to mode before the rename. Use for files that carry sensitive bytes
// (state tokens, private material) where the default umask-modified 0600
// might slip to 0644 on platforms where the temp file is created with a
// looser mode.
//
// Pass mode=0 to inherit os.CreateTemp's 0600 default.
//
// Same rename/fsync guarantees as WriteFileAtomic: temp is fsync'd, then
// renamed, then parent dir is fsync'd. Symlinks at path are refused.
func WriteFileAtomicMode(path string, data []byte, mode os.FileMode) error {
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("refuse to write to %s: target is a symbolic link", path)
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("lstat %s: %w", path, err)
	}

	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("create temp in %s: %w", dir, err)
	}
	tmp := f.Name()
	cleanup := func() { _ = os.Remove(tmp) }

	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		cleanup()
		return fmt.Errorf("write temp %s: %w", tmp, err)
	}
	if mode != 0 {
		if err := f.Chmod(mode); err != nil {
			_ = f.Close()
			cleanup()
			return fmt.Errorf("chmod temp %s: %w", tmp, err)
		}
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		cleanup()
		return fmt.Errorf("sync temp %s: %w", tmp, err)
	}
	if err := f.Close(); err != nil {
		cleanup()
		return fmt.Errorf("close temp %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		cleanup()
		return fmt.Errorf("rename %s -> %s: %w", tmp, path, err)
	}
	// fsync the parent dir so the rename itself is durable across a crash.
	// No-op on Windows (directory Sync is not meaningful); best-effort elsewhere.
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}
