package docker

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/charmbracelet/log"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/events"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/client"
)

// Watcher monitors Docker events and manages container-based proxies
type Watcher struct {
	client *client.Client
	ctx    context.Context
	cancel context.CancelFunc

	// Callbacks
	onAdd    func(info ContainerInfo) error
	onRemove func(domain string)

	// Container ID -> Domain mapping
	containerMap sync.Map // map[string]string
}

// NewWatcher creates a new Docker watcher
func NewWatcher(ctx context.Context, socketPath string) (*Watcher, error) {
	opts := []client.Opt{
		client.FromEnv,
		client.WithAPIVersionNegotiation(),
	}

	if socketPath != "" {
		opts = append(opts, client.WithHost("unix://"+socketPath))
	}

	cli, err := client.NewClientWithOpts(opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create Docker client: %w", err)
	}

	// Test connection
	if _, err := cli.Ping(ctx); err != nil {
		return nil, fmt.Errorf("failed to connect to Docker daemon: %w", err)
	}

	watcherCtx, cancel := context.WithCancel(ctx)

	return &Watcher{
		client: cli,
		ctx:    watcherCtx,
		cancel: cancel,
	}, nil
}

// OnContainerAdd sets the callback for when a container is added
func (w *Watcher) OnContainerAdd(callback func(info ContainerInfo) error) {
	w.onAdd = callback
}

// OnContainerRemove sets the callback for when a container is removed
func (w *Watcher) OnContainerRemove(callback func(domain string)) {
	w.onRemove = callback
}

// Start begins monitoring Docker events
func (w *Watcher) Start() error {
	// Scan existing containers first
	if err := w.scanExistingContainers(); err != nil {
		log.Warn("Failed to scan existing containers", "error", err)
	}

	// Start event monitoring
	go w.monitorEvents()

	log.Info("Docker watcher started")
	return nil
}

// Stop stops the watcher
func (w *Watcher) Stop() {
	w.cancel()
	if w.client != nil {
		w.client.Close()
	}
	log.Info("Docker watcher stopped")
}

// scanExistingContainers scans all running containers on startup
func (w *Watcher) scanExistingContainers() error {
	containers, err := w.client.ContainerList(w.ctx, container.ListOptions{})
	if err != nil {
		return fmt.Errorf("failed to list containers: %w", err)
	}

	log.Info("Scanning existing containers", "count", len(containers))

	for _, c := range containers {
		info, err := getContainerInfo(w.ctx, w.client, c.ID)
		if err != nil {
			log.Error("Failed to get container info", "container", c.ID, "error", err)
			continue
		}

		if info == nil {
			continue // No nexo labels
		}

		// Call the add callback
		if w.onAdd != nil {
			if err := w.onAdd(*info); err != nil {
				log.Error("Failed to add container proxy", "domain", info.Domain, "error", err)
			} else {
				// Store mapping
				w.containerMap.Store(info.ID, info.Domain)
			}
		}
	}

	return nil
}

// monitorEvents monitors Docker events in real-time
func (w *Watcher) monitorEvents() {
	// Create event filters
	f := filters.NewArgs()
	f.Add("type", "container")
	f.Add("event", "start")
	f.Add("event", "die")
	f.Add("event", "stop")

	for {
		eventChan, errChan := w.client.Events(w.ctx, events.ListOptions{
			Filters: f,
		})

		func() {
			for {
				select {
				case event := <-eventChan:
					w.handleEvent(event)

				case err := <-errChan:
					if err != nil {
						log.Error("Docker event stream error", "error", err)
					}
					return // Break inner loop to reconnect

				case <-w.ctx.Done():
					return
				}
			}
		}()

		// Check if context was cancelled
		if w.ctx.Err() != nil {
			return
		}

		// Reconnect after a delay
		log.Warn("Docker event stream disconnected, reconnecting in 5s")
		time.Sleep(5 * time.Second)
	}
}

// handleEvent processes Docker events
func (w *Watcher) handleEvent(event events.Message) {
	containerID := event.ID

	switch event.Action {
	case "start":
		w.handleContainerStart(containerID)

	case "die", "stop":
		w.handleContainerStop(containerID)
	}
}

// handleContainerStart handles container start events
func (w *Watcher) handleContainerStart(containerID string) {
	info, err := getContainerInfo(w.ctx, w.client, containerID)
	if err != nil {
		log.Error("Failed to get container info", "container", containerID, "error", err)
		return
	}

	if info == nil {
		return // No nexo labels
	}

	log.Debug("Container started with nexo labels", "domain", info.Domain, "container", info.Name)

	// Call the add callback
	if w.onAdd != nil {
		if err := w.onAdd(*info); err != nil {
			log.Error("Failed to add container proxy", "domain", info.Domain, "error", err)
			return
		}

		// Store mapping
		w.containerMap.Store(info.ID, info.Domain)
	}
}

// handleContainerStop handles container stop/die events
func (w *Watcher) handleContainerStop(containerID string) {
	// Retrieve domain from cache
	value, ok := w.containerMap.Load(containerID)
	if !ok {
		return // Not a nexo-managed container
	}

	domain, ok := value.(string)
	if !ok {
		log.Error("Invalid domain type in container map", "container", containerID)
		return
	}

	log.Debug("Container stopped", "domain", domain, "container", containerID)

	// Call the remove callback
	if w.onRemove != nil {
		w.onRemove(domain)
	}

	// Remove from cache
	w.containerMap.Delete(containerID)
}
