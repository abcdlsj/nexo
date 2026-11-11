// Package configstore owns the single writer for the nexo configuration file.
// The Web UI, the control plane and any future CLI all mutate through Store, so
// writes stay serialized and every reader sees an immutable snapshot.
package configstore

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/abcdlsj/nexo/pkg/config"
	"gopkg.in/yaml.v3"
)

// Store serializes updates and publishes immutable config snapshots.
type Store struct {
	mu       sync.RWMutex
	updateMu sync.Mutex
	current  *config.Config
	path     string
	onChange func() error
}

// New builds a store around an initial snapshot. onChange runs after a
// successful write and must reload the running server; if it fails the write is
// rolled back.
func New(initial *config.Config, path string, onChange func() error) *Store {
	return &Store{current: Clone(initial), path: path, onChange: onChange}
}

// Snapshot returns the current immutable config.
func (s *Store) Snapshot() *config.Config {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.current
}

// Path returns the configuration file path owned by the store.
func (s *Store) Path() string { return s.path }

// Replace publishes an externally loaded snapshot (for example after a file
// watcher reload).
func (s *Store) Replace(next *config.Config) {
	s.mu.Lock()
	s.current = Clone(next)
	s.mu.Unlock()
}

// Update applies a mutation, writes the file atomically and reloads. A reload
// failure restores both the file and the previous snapshot.
func (s *Store) Update(mutate func(*config.Config) error) error {
	s.updateMu.Lock()
	defer s.updateMu.Unlock()

	previous := s.Snapshot()
	next := Clone(previous)
	if err := mutate(next); err != nil {
		return err
	}

	previousData, err := yaml.Marshal(previous)
	if err != nil {
		return fmt.Errorf("marshal previous config: %w", err)
	}
	nextData, err := yaml.Marshal(next)
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	if err := WriteFileAtomic(s.path, nextData, 0600); err != nil {
		return fmt.Errorf("write config: %w", err)
	}
	if s.onChange != nil {
		if err := s.onChange(); err != nil {
			rollbackErr := WriteFileAtomic(s.path, previousData, 0600)
			if rollbackErr == nil {
				rollbackErr = s.onChange()
			}
			if rollbackErr != nil {
				return fmt.Errorf("reload: %w; rollback: %v", err, rollbackErr)
			}
			return fmt.Errorf("reload: %w", err)
		}
	}
	s.Replace(next)
	return nil
}

// WriteFileAtomic writes data to a temp file in the same directory and renames
// it, so a crash never leaves a partially written config.
func WriteFileAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".nexo-config-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

// Clone deep-copies a config through YAML so callers never share maps.
func Clone(source *config.Config) *config.Config {
	if source == nil {
		return &config.Config{}
	}
	data, err := yaml.Marshal(source)
	if err != nil {
		panic(fmt.Sprintf("clone config: %v", err))
	}
	var clone config.Config
	if err := yaml.Unmarshal(data, &clone); err != nil {
		panic(fmt.Sprintf("clone config: %v", err))
	}
	return &clone
}
