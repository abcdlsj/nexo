package docker

import (
	"context"
	"encoding/json"
	"io"
	"strings"
	"time"

	"github.com/charmbracelet/log"
)

const (
	eventDebounce  = 300 * time.Millisecond
	reconnectDelay = 2 * time.Second
)

// Watcher keeps a route set in sync with the containers the daemon reports.
//
// It deliberately treats Docker events as a change signal only: every signal
// re-lists containers and hands over the complete desired route set. Reconciling
// a full set is smaller than tracking per-container deltas, and it cannot drift
// when events are missed, coalesced, or replayed across a reconnect.
type Watcher struct {
	socket       string
	fallbackHost string
	onRoutes     func([]Route)
	fingerprint  string
}

// NewWatcher builds a watcher; onRoutes is called with the full route set every
// time the observed set changes.
func NewWatcher(socket, fallbackHost string, onRoutes func([]Route)) *Watcher {
	return &Watcher{socket: socket, fallbackHost: fallbackHost, onRoutes: onRoutes}
}

// Run blocks until ctx is cancelled, resubscribing to the event stream whenever
// the daemon closes it.
func (w *Watcher) Run(ctx context.Context) {
	client := NewClient(w.socket)
	trigger := make(chan struct{}, 1)

	go w.reconcileLoop(ctx, client, trigger)

	for ctx.Err() == nil {
		body, err := client.Events(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Warn("Docker event stream unavailable", "err", err)
		} else {
			// Sync after subscribing so nothing that happened between the list
			// and the subscribe can be missed.
			w.sync(ctx, client)
			w.pump(ctx, body, trigger)
			body.Close()
			if ctx.Err() != nil {
				return
			}
		}

		select {
		case <-ctx.Done():
			return
		case <-time.After(reconnectDelay):
		}
	}
}

// reconcileLoop coalesces bursts of events into one rescan.
func (w *Watcher) reconcileLoop(ctx context.Context, client *Client, trigger <-chan struct{}) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-trigger:
		}

		timer := time.NewTimer(eventDebounce)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		select {
		case <-trigger: // a newer signal supersedes this scan
		default:
		}

		w.sync(ctx, client)
	}
}

func (w *Watcher) pump(ctx context.Context, body io.Reader, trigger chan<- struct{}) {
	decoder := json.NewDecoder(body)
	for {
		var event Event
		if err := decoder.Decode(&event); err != nil {
			return
		}
		if event.Type != "" && event.Type != "container" {
			continue
		}
		select {
		case trigger <- struct{}{}:
		default:
		}
	}
}

func (w *Watcher) sync(ctx context.Context, client *Client) {
	containers, err := client.ListContainers(ctx, labelKeys)
	if err != nil {
		if ctx.Err() == nil {
			log.Error("Docker container scan failed", "err", err)
		}
		return
	}

	routes := Routes(containers, w.fallbackHost)
	fingerprint := fingerprint(routes)
	if fingerprint == w.fingerprint {
		return
	}
	w.fingerprint = fingerprint

	log.Info("Docker routes changed", "routes", len(routes))
	if w.onRoutes != nil {
		w.onRoutes(routes)
	}
}

func fingerprint(routes []Route) string {
	var b strings.Builder
	for _, route := range routes {
		b.WriteString(route.Domain)
		b.WriteByte('=')
		b.WriteString(route.Upstream)
		if route.Auth {
			b.WriteString("|auth")
		}
		b.WriteByte('\n')
	}
	return b.String()
}
