package webui

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/abcdlsj/nexo/pkg/config"
	"gopkg.in/yaml.v3"
)

func TestConfigStoreRollback(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "config.yaml")
	initial := &config.Config{Email: "before@example.com", Wildcards: []string{"*.example.com"}}
	writeTestConfig(t, path, initial)

	reloadFailure := errors.New("reload failed")
	var reloads atomic.Int32
	store := newConfigStore(initial, path, func() error {
		if reloads.Add(1) == 1 {
			return reloadFailure
		}
		return nil
	})

	err := store.update(func(next *config.Config) error {
		next.Email = "after@example.com"
		return nil
	})
	if !errors.Is(err, reloadFailure) {
		t.Fatalf("update error = %v, want reload failure", err)
	}
	if got := store.snapshot().Email; got != initial.Email {
		t.Fatalf("snapshot email = %q, want %q", got, initial.Email)
	}
	if got := readTestConfig(t, path).Email; got != initial.Email {
		t.Fatalf("persisted email = %q, want %q", got, initial.Email)
	}
	if got := reloads.Load(); got != 2 {
		t.Fatalf("reload calls = %d, want 2", got)
	}
}

func TestConfigStoreConcurrency(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "config.yaml")
	initial := &config.Config{}
	writeTestConfig(t, path, initial)
	store := newConfigStore(initial, path, nil)

	const updates = 10
	errs := make(chan error, updates)
	var wg sync.WaitGroup
	for i := 0; i < updates; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- store.update(func(next *config.Config) error {
				next.Wildcards = append(next.Wildcards, fmt.Sprintf("*.route-%d.example.com", i))
				return nil
			})
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent update: %v", err)
		}
	}

	assertWildcards := func(label string, wildcards []string) {
		t.Helper()
		seen := make(map[string]bool, len(wildcards))
		for _, wildcard := range wildcards {
			seen[wildcard] = true
		}
		if len(seen) != updates {
			t.Fatalf("%s contains %d unique updates, want %d: %v", label, len(seen), updates, wildcards)
		}
		for i := 0; i < updates; i++ {
			want := fmt.Sprintf("*.route-%d.example.com", i)
			if !seen[want] {
				t.Errorf("%s missing %q", label, want)
			}
		}
	}
	assertWildcards("snapshot", store.snapshot().Wildcards)
	assertWildcards("file", readTestConfig(t, path).Wildcards)
}

func writeTestConfig(t *testing.T, path string, cfg *config.Config) {
	t.Helper()
	data, err := yaml.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeFileAtomic(path, data, 0600); err != nil {
		t.Fatal(err)
	}
}

func readTestConfig(t *testing.T, path string) *config.Config {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var cfg config.Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		t.Fatal(err)
	}
	return &cfg
}
