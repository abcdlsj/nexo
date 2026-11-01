package server

import (
	"context"
	"sort"
	"strings"

	"github.com/abcdlsj/nexo/internal/webui"
	"github.com/abcdlsj/nexo/pkg/config"
	"github.com/abcdlsj/nexo/pkg/docker"
	"github.com/abcdlsj/nexo/pkg/proxy"
	"github.com/charmbracelet/log"
)

const defaultDockerSocket = "/var/run/docker.sock"

// dockerRoute is one live route discovered from container labels.
type dockerRoute struct {
	cfg       *proxy.Config
	handler   *proxy.Handler
	container string
}

func dockerSocket(cfg *config.Config) string {
	if cfg == nil || strings.TrimSpace(cfg.Docker.Socket) == "" {
		return defaultDockerSocket
	}
	return cfg.Docker.Socket
}

func (s *Server) dockerRoute(domain string) (*dockerRoute, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	route, ok := s.dockerRoutes[domain]
	return route, ok
}

// hasRoute reports whether a domain is served, statically or by a container.
func (s *Server) hasRoute(domain string) bool {
	if _, ok := s.config().Proxies[domain]; ok {
		return true
	}
	_, ok := s.dockerRoute(domain)
	return ok
}

// routeDomains lists every served domain for certificate renewal.
func (s *Server) routeDomains() []string {
	cfg := s.config()
	domains := make([]string, 0, len(cfg.Proxies))
	for domain := range cfg.Proxies {
		domains = append(domains, domain)
	}

	s.mu.RLock()
	for domain := range s.dockerRoutes {
		domains = append(domains, domain)
	}
	s.mu.RUnlock()

	sort.Strings(domains)
	return domains
}

func (s *Server) authAllowedHosts() []string {
	cfg := s.config()
	hosts := make([]string, 0, len(cfg.Proxies))
	for domain := range cfg.Proxies {
		hosts = append(hosts, domain)
	}

	s.mu.RLock()
	for domain := range s.dockerRoutes {
		hosts = append(hosts, domain)
	}
	s.mu.RUnlock()

	return hosts
}

func (s *Server) refreshAuthHosts() {
	if s.authm == nil {
		return
	}
	s.authm.UpdateAllowedHosts(s.authAllowedHosts())
}

// dynamicWebRoutes exposes discovered routes to the Web UI as read-only entries.
func (s *Server) dynamicWebRoutes() map[string]webui.DynamicRoute {
	s.mu.RLock()
	defer s.mu.RUnlock()

	routes := make(map[string]webui.DynamicRoute, len(s.dockerRoutes))
	for domain, route := range s.dockerRoutes {
		routes[domain] = webui.DynamicRoute{Upstream: route.cfg.Upstream, Container: route.container}
	}
	return routes
}

// syncDockerWatcher starts, stops, or repoints container discovery so the
// running watcher matches cfg. It is safe to call on every reload.
func (s *Server) syncDockerWatcher(cfg *config.Config) {
	enabled := cfg != nil && cfg.Docker.Enabled
	socket := dockerSocket(cfg)

	s.mu.RLock()
	running := s.dockerCancel != nil
	current := s.dockerSocket
	s.mu.RUnlock()

	if !enabled {
		if running {
			s.stopDockerWatcher()
		}
		return
	}
	if running && current == socket {
		return
	}
	if running {
		s.stopDockerWatcher()
	}
	s.startDockerWatcher(cfg)
}

func (s *Server) startDockerWatcher(cfg *config.Config) {
	socket := dockerSocket(cfg)
	host := strings.TrimSpace(cfg.Docker.Host)
	if host == "" {
		host = "127.0.0.1"
	}

	ctx, cancel := context.WithCancel(s.ctx)
	s.mu.Lock()
	s.dockerCancel = cancel
	s.dockerSocket = socket
	s.mu.Unlock()

	go docker.NewWatcher(socket, host, s.applyDockerRoutes).Run(ctx)
	log.Info("Docker label discovery enabled", "socket", socket)
}

func (s *Server) stopDockerWatcher() {
	s.mu.Lock()
	cancel := s.dockerCancel
	s.dockerCancel = nil
	s.dockerSocket = ""
	s.mu.Unlock()

	if cancel != nil {
		cancel()
		log.Info("Docker label discovery stopped")
	}
	s.applyDockerRoutes(nil)
}

// applyDockerRoutes replaces the discovered route set with routes.
func (s *Server) applyDockerRoutes(routes []docker.Route) {
	s.mu.RLock()
	active := s.dockerCancel != nil
	s.mu.RUnlock()
	if !active {
		// Discovery was turned off while this scan was in flight.
		routes = nil
	}

	cfg := s.config()
	next := make(map[string]*dockerRoute, len(routes))
	for _, route := range routes {
		if _, static := cfg.Proxies[route.Domain]; static {
			log.Warn("Docker route skipped: domain is set in the config file", "domain", route.Domain, "container", route.Container)
			continue
		}

		routeCfg := &proxy.Config{Upstream: route.Upstream, Auth: route.Auth}
		if previous, ok := s.dockerRoute(route.Domain); ok &&
			previous.cfg.Upstream == routeCfg.Upstream && previous.cfg.Auth == routeCfg.Auth {
			next[route.Domain] = previous
			continue
		}

		handler, err := s.createProxyHandler(route.Domain, routeCfg)
		if err != nil {
			log.Error("Docker route skipped", "domain", route.Domain, "container", route.Container, "err", err)
			// Keep serving the previous handler rather than dropping traffic on
			// a transient failure.
			if previous, ok := s.dockerRoute(route.Domain); ok {
				next[route.Domain] = previous
			}
			continue
		}
		next[route.Domain] = &dockerRoute{cfg: routeCfg, handler: handler, container: route.Container}
	}

	s.mu.Lock()
	previous := s.dockerRoutes
	s.dockerRoutes = next
	s.mu.Unlock()

	for domain, route := range next {
		if _, existed := previous[domain]; !existed {
			log.Info("Docker route added", "domain", domain, "container", route.container, "upstream", route.cfg.Upstream)
		}
	}
	for domain := range previous {
		if _, kept := next[domain]; !kept {
			log.Info("Docker route removed", "domain", domain)
		}
	}

	s.refreshAuthHosts()
}
