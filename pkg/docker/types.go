package docker

// ContainerInfo represents container information extracted from Docker labels
type ContainerInfo struct {
	ID       string // Container ID
	Name     string // Container name
	Domain   string // Domain from nexo.domain label
	Port     string // Port from nexo.port label
	Protocol string // Protocol from nexo.protocol label (http/https)
	Upstream string // Full upstream address (e.g., http://container-name:8080)
}
