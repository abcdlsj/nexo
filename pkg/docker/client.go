package docker

import (
	"context"
	"fmt"
	"strings"

	"github.com/charmbracelet/log"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
	"github.com/docker/go-connections/nat"
)

// parseLabels parses container labels to extract Nexo configuration
func parseLabels(inspect container.InspectResponse) *ContainerInfo {
	labels := inspect.Config.Labels

	domain := labels["nexo.domain"]
	port := labels["nexo.port"]

	// Skip containers without required labels
	if domain == "" || port == "" {
		return nil
	}

	protocol := labels["nexo.protocol"]
	if protocol == "" {
		protocol = "http"
	}

	// Determine the best upstream address
	// Priority: container name > host port mapping > container IP
	name := strings.TrimPrefix(inspect.Name, "/")
	upstream := determineUpstream(inspect, name, port, protocol)

	return &ContainerInfo{
		ID:       inspect.ID,
		Name:     name,
		Domain:   domain,
		Port:     port,
		Protocol: protocol,
		Upstream: upstream, // Store the full upstream address
	}
}

// determineUpstream determines the best upstream address for the container
func determineUpstream(inspect container.InspectResponse, name, port, protocol string) string {
	// Priority 1: Use container name (works if containers are in the same network)
	// This is the most reliable method for Docker networks
	if len(inspect.NetworkSettings.Networks) > 0 {
		log.Debug("Using container name for upstream", "container", name)
		return fmt.Sprintf("%s://%s:%s", protocol, name, port)
	}

	// Priority 2: Check for port mappings (works when container exposes ports to host)
	if inspect.HostConfig != nil && inspect.HostConfig.PortBindings != nil {
		portKey := nat.Port(port + "/tcp")
		if portBindings, exists := inspect.HostConfig.PortBindings[portKey]; exists && len(portBindings) > 0 {
			hostPort := portBindings[0].HostPort
			log.Debug("Using host port mapping for upstream", "container", name, "hostPort", hostPort)
			// Use host.docker.internal for Docker Desktop, or 172.17.0.1 for Linux
			return fmt.Sprintf("%s://host.docker.internal:%s", protocol, hostPort)
		}
	}

	// Priority 3: Use container IP (least reliable, IP changes on restart)
	ip := inspect.NetworkSettings.IPAddress
	if ip != "" {
		log.Warn("Using container IP for upstream (may break on restart)", "container", name, "ip", ip)
		return fmt.Sprintf("%s://%s:%s", protocol, ip, port)
	}

	// Fallback: use container name anyway
	log.Warn("Could not determine upstream address, using container name", "container", name)
	return fmt.Sprintf("%s://%s:%s", protocol, name, port)
}

// getContainerInfo retrieves and parses container information
func getContainerInfo(ctx context.Context, cli *client.Client, containerID string) (*ContainerInfo, error) {
	inspect, err := cli.ContainerInspect(ctx, containerID)
	if err != nil {
		return nil, fmt.Errorf("failed to inspect container %s: %w", containerID, err)
	}

	info := parseLabels(inspect)
	if info == nil {
		log.Debug("Container has no nexo labels, skipping", "container", containerID)
		return nil, nil
	}

	return info, nil
}
