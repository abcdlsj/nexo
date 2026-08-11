package webui

import (
	"fmt"
	"sync"

	"github.com/abcdlsj/nexo/pkg/config"
	"gopkg.in/yaml.v3"
)

// configStore owns the Web UI's immutable config snapshot and serializes every
// persisted update. Readers never observe a map while it is being mutated.
type configStore struct {
	mu       sync.RWMutex
	updateMu sync.Mutex
	current  *config.Config
	path     string
	onChange func() error
}

func newConfigStore(initial *config.Config, path string, onChange func() error) *configStore {
	return &configStore{current: cloneConfig(initial), path: path, onChange: onChange}
}

func (s *configStore) snapshot() *config.Config {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.current
}

func (s *configStore) replace(next *config.Config) {
	s.mu.Lock()
	s.current = cloneConfig(next)
	s.mu.Unlock()
}

func (s *configStore) update(mutate func(*config.Config) error) error {
	s.updateMu.Lock()
	defer s.updateMu.Unlock()

	previous := s.snapshot()
	next := cloneConfig(previous)
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
	if err := writeFileAtomic(s.path, nextData, 0600); err != nil {
		return fmt.Errorf("write config: %w", err)
	}
	if s.onChange != nil {
		if err := s.onChange(); err != nil {
			rollbackErr := writeFileAtomic(s.path, previousData, 0600)
			if rollbackErr == nil {
				rollbackErr = s.onChange()
			}
			if rollbackErr != nil {
				return fmt.Errorf("reload: %w; rollback: %v", err, rollbackErr)
			}
			return fmt.Errorf("reload: %w", err)
		}
	}
	s.replace(next)
	return nil
}

func cloneConfig(source *config.Config) *config.Config {
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
