package docker

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/charmbracelet/log"
)

// Labels read from a container. Only Domain is required; everything else falls
// back to something sane so the common case stays one label:
//
//	docker run -d --label nexo.domain=api.example.com my-api
const (
	LabelDomain   = "nexo.domain"   // required, comma-separated for several domains
	LabelPort     = "nexo.port"     // optional, defaults to the single exposed TCP port
	LabelUpstream = "nexo.upstream" // optional, full URL, wins over inference
	LabelNetwork  = "nexo.network"  // optional, pin the Docker network to read the IP from
	LabelAuth     = "nexo.auth"     // optional, require GitHub OAuth like a config route
)

// labelKeys are the labels that make a container interesting to Nexo. They are
// pushed to the daemon as filters so unrelated containers are never returned.
var labelKeys = []string{LabelDomain, LabelPort, LabelUpstream, LabelNetwork, LabelAuth}

// Route is one proxy route discovered from container labels.
type Route struct {
	Domain    string
	Upstream  string
	Auth      bool
	Container string
}

// Routes converts running containers into proxy routes. Containers without a
// domain label or without a resolvable port are skipped with a log line rather
// than failing the whole scan.
//
// fallbackHost is used when the upstream has to be reached through a published
// host port, e.g. "127.0.0.1" for a Nexo process running next to the daemon.
func Routes(containers []Container, fallbackHost string) []Route {
	routes := make([]Route, 0, len(containers))
	for _, container := range containers {
		name := containerName(container)

		domains := parseDomains(container.Labels[LabelDomain])
		if len(domains) == 0 {
			continue
		}

		port, err := parsePort(container)
		if err != nil {
			log.Warn("Skipping container with unusable port label", "container", name, "err", err)
			continue
		}

		upstream, source := upstreamFor(container, port, fallbackHost)
		log.Debug("Docker route resolved", "container", name, "upstream", upstream, "via", source)

		for _, domain := range domains {
			routes = append(routes, Route{
				Domain:    domain,
				Upstream:  upstream,
				Auth:      parseBool(container.Labels[LabelAuth]),
				Container: name,
			})
		}
	}

	sort.Slice(routes, func(i, j int) bool { return routes[i].Domain < routes[j].Domain })
	return routes
}

// parseDomains splits the domain label, tolerant of spaces and case.
func parseDomains(raw string) []string {
	fields := strings.Split(raw, ",")
	domains := make([]string, 0, len(fields))
	for _, field := range fields {
		domain := strings.ToLower(strings.TrimSpace(field))
		if domain != "" {
			domains = append(domains, domain)
		}
	}
	return domains
}

// parsePort reads nexo.port, or infers it when the container exposes exactly
// one TCP port. Ambiguous cases prefer a published port.
func parsePort(container Container) (int, error) {
	if raw := strings.TrimSpace(container.Labels[LabelPort]); raw != "" {
		port, err := strconv.Atoi(raw)
		if err != nil || port <= 0 || port > 65535 {
			return 0, fmt.Errorf("%s=%q is not a valid port", LabelPort, raw)
		}
		return port, nil
	}

	exposed := map[int]int{} // private port -> published port (0 when unpublished)
	for _, p := range container.Ports {
		if !strings.EqualFold(p.Type, "tcp") || p.PrivatePort <= 0 {
			continue
		}
		if published, ok := exposed[p.PrivatePort]; !ok || (published == 0 && p.PublicPort > 0) {
			exposed[p.PrivatePort] = p.PublicPort
		}
	}
	if len(exposed) == 0 {
		return 0, fmt.Errorf("no TCP port exposed; set %s", LabelPort)
	}

	ports := make([]int, 0, len(exposed))
	for port := range exposed {
		ports = append(ports, port)
	}
	sort.Ints(ports)
	if len(ports) == 1 {
		return ports[0], nil
	}

	for _, port := range ports {
		if exposed[port] > 0 {
			return port, nil
		}
	}
	return ports[0], nil
}

// upstreamFor picks the target URL, most-specific source first, and reports
// which one was used for logging.
func upstreamFor(container Container, port int, fallbackHost string) (string, string) {
	if raw := strings.TrimSpace(container.Labels[LabelUpstream]); raw != "" {
		return withScheme(raw), "label"
	}

	if ip := networkIP(container); ip != "" {
		return fmt.Sprintf("http://%s:%d", ip, port), "network"
	}

	if publicPort := publishedPort(container, port); publicPort > 0 {
		if fallbackHost == "" {
			fallbackHost = "127.0.0.1"
		}
		return fmt.Sprintf("http://%s:%d", fallbackHost, publicPort), "published"
	}

	// Last resort: containers on a user-defined network resolve each other by
	// name through Docker's embedded DNS.
	return fmt.Sprintf("http://%s:%d", containerName(container), port), "name"
}

// networkIP returns the container IP on the pinned network, or on the
// alphabetically first attached network that has an address.
func networkIP(container Container) string {
	networks := container.NetworkSettings.Networks
	if len(networks) == 0 {
		return ""
	}

	if pinned := strings.TrimSpace(container.Labels[LabelNetwork]); pinned != "" {
		if endpoint, ok := networks[pinned]; ok && endpoint.IPAddress != "" {
			return endpoint.IPAddress
		}
		log.Warn("Pinned network not attached to container", "network", pinned, "container", containerName(container))
	}

	names := make([]string, 0, len(networks))
	for name := range networks {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if ip := networks[name].IPAddress; ip != "" {
			return ip
		}
	}
	return ""
}

func publishedPort(container Container, port int) int {
	for _, p := range container.Ports {
		if p.PrivatePort == port && p.PublicPort > 0 && strings.EqualFold(p.Type, "tcp") {
			return p.PublicPort
		}
	}
	return 0
}

func containerName(container Container) string {
	if len(container.Names) > 0 {
		if name := strings.TrimPrefix(container.Names[0], "/"); name != "" {
			return name
		}
	}
	if len(container.ID) > 12 {
		return container.ID[:12]
	}
	return container.ID
}

func parseBool(raw string) bool {
	value, err := strconv.ParseBool(strings.TrimSpace(raw))
	return err == nil && value
}

// withScheme accepts a bare host:port in nexo.upstream as well as a full URL.
func withScheme(target string) string {
	if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
		return target
	}
	return "http://" + target
}
