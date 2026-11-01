package docker

import "testing"

func containerWith(labels map[string]string, ports []Port, networks map[string]string) Container {
	c := Container{ID: "0123456789abcdef", Names: []string{"/my-api"}, Labels: labels, Ports: ports}
	if len(networks) > 0 {
		c.NetworkSettings.Networks = make(map[string]NetworkEndpoint, len(networks))
		for name, ip := range networks {
			c.NetworkSettings.Networks[name] = NetworkEndpoint{IPAddress: ip}
		}
	}
	return c
}

func TestRoutesRequireDomainLabel(t *testing.T) {
	t.Parallel()
	containers := []Container{
		containerWith(map[string]string{LabelPort: "8080"}, []Port{{PrivatePort: 8080, Type: "tcp"}}, nil),
	}
	if routes := Routes(containers, "127.0.0.1"); len(routes) != 0 {
		t.Fatalf("expected no routes without a domain label, got %+v", routes)
	}
}

func TestRoutesInferSingleExposedPort(t *testing.T) {
	t.Parallel()
	containers := []Container{
		containerWith(
			map[string]string{LabelDomain: "API.Example.com"},
			[]Port{{PrivatePort: 8080, Type: "tcp"}},
			map[string]string{"app": "172.18.0.5"},
		),
	}
	routes := Routes(containers, "127.0.0.1")
	if len(routes) != 1 {
		t.Fatalf("expected one route, got %+v", routes)
	}
	route := routes[0]
	if route.Domain != "api.example.com" {
		t.Fatalf("domain not normalised: %q", route.Domain)
	}
	if route.Upstream != "http://172.18.0.5:8080" {
		t.Fatalf("unexpected upstream: %q", route.Upstream)
	}
	if route.Container != "my-api" {
		t.Fatalf("unexpected container name: %q", route.Container)
	}
}

func TestRoutesPreferPublishedPortWhenAmbiguous(t *testing.T) {
	t.Parallel()
	containers := []Container{
		containerWith(
			map[string]string{LabelDomain: "app.example.com"},
			[]Port{
				{PrivatePort: 3000, Type: "tcp"},
				{PrivatePort: 8080, Type: "tcp", PublicPort: 18080},
			},
			map[string]string{"app": "172.18.0.7"},
		),
	}
	route := Routes(containers, "127.0.0.1")[0]
	if route.Upstream != "http://172.18.0.7:8080" {
		t.Fatalf("expected published port to win, got %q", route.Upstream)
	}
}

func TestRoutesUsePortLabel(t *testing.T) {
	t.Parallel()
	containers := []Container{
		containerWith(
			map[string]string{LabelDomain: "app.example.com", LabelPort: "9000"},
			[]Port{{PrivatePort: 3000, Type: "tcp"}},
			map[string]string{"app": "172.18.0.9"},
		),
	}
	route := Routes(containers, "127.0.0.1")[0]
	if route.Upstream != "http://172.18.0.9:9000" {
		t.Fatalf("port label ignored: %q", route.Upstream)
	}
}

func TestRoutesRejectInvalidPortLabel(t *testing.T) {
	t.Parallel()
	containers := []Container{
		containerWith(
			map[string]string{LabelDomain: "app.example.com", LabelPort: "http"},
			[]Port{{PrivatePort: 3000, Type: "tcp"}},
			map[string]string{"app": "172.18.0.9"},
		),
	}
	if routes := Routes(containers, "127.0.0.1"); len(routes) != 0 {
		t.Fatalf("expected invalid port label to drop the route, got %+v", routes)
	}
}

func TestRoutesSkipContainerWithoutPort(t *testing.T) {
	t.Parallel()
	containers := []Container{
		containerWith(map[string]string{LabelDomain: "app.example.com"}, nil, map[string]string{"app": "172.18.0.9"}),
	}
	if routes := Routes(containers, "127.0.0.1"); len(routes) != 0 {
		t.Fatalf("expected route without a port to be skipped, got %+v", routes)
	}
}

func TestRoutesPinNetwork(t *testing.T) {
	t.Parallel()
	containers := []Container{
		containerWith(
			map[string]string{LabelDomain: "app.example.com", LabelPort: "8080", LabelNetwork: "edge"},
			nil,
			map[string]string{"app": "172.18.0.9", "edge": "10.5.0.3"},
		),
	}
	route := Routes(containers, "127.0.0.1")[0]
	if route.Upstream != "http://10.5.0.3:8080" {
		t.Fatalf("pinned network ignored: %q", route.Upstream)
	}
}

func TestRoutesFallBackToPublishedPort(t *testing.T) {
	t.Parallel()
	containers := []Container{
		containerWith(
			map[string]string{LabelDomain: "app.example.com"},
			[]Port{{PrivatePort: 8080, Type: "tcp", PublicPort: 18080}},
			nil,
		),
	}
	route := Routes(containers, "192.168.1.10")[0]
	if route.Upstream != "http://192.168.1.10:18080" {
		t.Fatalf("expected published host port fallback, got %q", route.Upstream)
	}
}

func TestRoutesFallBackToContainerName(t *testing.T) {
	t.Parallel()
	containers := []Container{
		containerWith(
			map[string]string{LabelDomain: "app.example.com", LabelPort: "8080"},
			nil,
			nil,
		),
	}
	route := Routes(containers, "")[0]
	if route.Upstream != "http://my-api:8080" {
		t.Fatalf("expected container name fallback, got %q", route.Upstream)
	}
}

func TestRoutesHonourUpstreamLabel(t *testing.T) {
	t.Parallel()
	containers := []Container{
		containerWith(
			map[string]string{LabelDomain: "app.example.com", LabelPort: "8080", LabelUpstream: "https://10.0.0.2:8443"},
			nil,
			map[string]string{"app": "172.18.0.9"},
		),
	}
	route := Routes(containers, "127.0.0.1")[0]
	if route.Upstream != "https://10.0.0.2:8443" {
		t.Fatalf("upstream label ignored: %q", route.Upstream)
	}
}

func TestRoutesExpandDomainsAndAuth(t *testing.T) {
	t.Parallel()
	containers := []Container{
		containerWith(
			map[string]string{LabelDomain: "a.example.com, b.example.com", LabelPort: "8080", LabelAuth: "true"},
			nil,
			map[string]string{"app": "172.18.0.9"},
		),
	}
	routes := Routes(containers, "127.0.0.1")
	if len(routes) != 2 {
		t.Fatalf("expected two routes, got %+v", routes)
	}
	if routes[0].Domain != "a.example.com" || routes[1].Domain != "b.example.com" {
		t.Fatalf("routes not sorted by domain: %+v", routes)
	}
	for _, route := range routes {
		if !route.Auth {
			t.Fatalf("auth label ignored: %+v", route)
		}
	}
}
