package docker

import (
	"context"
	"net"
	"net/http"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// startEvent is the shape the daemon streams on container start.
const startEvent = `{"Type":"container","Action":"start","Actor":{"ID":"abc"}}`

// fakeDaemon serves the two endpoints the watcher uses over a unix socket.
type fakeDaemon struct {
	mu         sync.Mutex
	containers string
	events     chan string
}

func (d *fakeDaemon) setContainers(payload string) {
	d.mu.Lock()
	d.containers = payload
	d.mu.Unlock()
}

func (d *fakeDaemon) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/containers/json":
		d.mu.Lock()
		payload := d.containers
		d.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(payload))
	case "/events":
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		for {
			select {
			case <-r.Context().Done():
				return
			case event := <-d.events:
				_, _ = w.Write([]byte(event + "\n"))
				w.(http.Flusher).Flush()
			}
		}
	default:
		http.NotFound(w, r)
	}
}

func startFakeDaemon(t *testing.T) (*fakeDaemon, string) {
	t.Helper()
	socket := filepath.Join(t.TempDir(), "docker.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	daemon := &fakeDaemon{events: make(chan string, 4)}
	server := &http.Server{Handler: daemon}
	go server.Serve(listener)
	t.Cleanup(func() {
		server.Close()
		listener.Close()
	})
	return daemon, socket
}

func TestWatcherPublishesRouteSet(t *testing.T) {
	t.Parallel()
	daemon, socket := startFakeDaemon(t)
	daemon.setContainers(`[{"Id":"abc","Names":["/api"],"Labels":{"nexo.domain":"api.example.com","nexo.port":"8080"},"Ports":[],"NetworkSettings":{"Networks":{"app":{"IPAddress":"172.18.0.4"}}}}]`)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	updates := make(chan []Route, 8)
	watcher := NewWatcher(socket, "127.0.0.1", func(routes []Route) { updates <- routes })
	go watcher.Run(ctx)

	first := waitForRoutes(t, updates)
	if len(first) != 1 || first[0].Upstream != "http://172.18.0.4:8080" {
		t.Fatalf("unexpected initial routes: %+v", first)
	}

	daemon.setContainers(`[{"Id":"abc","Names":["/api"],"Labels":{"nexo.domain":"api.example.com","nexo.port":"9090"},"Ports":[],"NetworkSettings":{"Networks":{"app":{"IPAddress":"172.18.0.4"}}}}]`)
	daemon.events <- startEvent

	second := waitForRoutes(t, updates)
	if len(second) != 1 || second[0].Upstream != "http://172.18.0.4:9090" {
		t.Fatalf("watcher did not pick up the port change: %+v", second)
	}

	daemon.setContainers(`[]`)
	daemon.events <- startEvent

	third := waitForRoutes(t, updates)
	if len(third) != 0 {
		t.Fatalf("expected the route set to be cleared, got %+v", third)
	}
}

func waitForRoutes(t *testing.T, updates <-chan []Route) []Route {
	t.Helper()
	select {
	case routes := <-updates:
		return routes
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for a route update")
		return nil
	}
}
