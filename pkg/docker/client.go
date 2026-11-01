package docker

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"
)

// Client is a minimal Docker Engine API client. Only the endpoints Nexo needs
// are implemented, over the unix socket, so no Docker SDK (and no transitive
// OpenTelemetry/gRPC tree) is pulled into the build.
//
// The unversioned paths below are served by every supported daemon version; the
// daemon replies with its own negotiated payload shape, of which the client
// decodes only the fields it understands.
type Client struct {
	httpc *http.Client
}

// NewClient returns a client that talks to the daemon listening on socket.
func NewClient(socket string) *Client {
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var dialer net.Dialer
			return dialer.DialContext(ctx, "unix", socket)
		},
		MaxIdleConns:    2,
		IdleConnTimeout: 30 * time.Second,
	}
	return &Client{httpc: &http.Client{Transport: transport}}
}

// Port is one entry of a container's published/exposed port list.
type Port struct {
	PrivatePort int    `json:"PrivatePort"`
	PublicPort  int    `json:"PublicPort"`
	Type        string `json:"Type"`
}

// NetworkEndpoint is the container's attachment to one Docker network.
type NetworkEndpoint struct {
	IPAddress string `json:"IPAddress"`
	NetworkID string `json:"NetworkID"`
}

// Container is the subset of /containers/json Nexo uses.
type Container struct {
	ID              string            `json:"Id"`
	Names           []string          `json:"Names"`
	Image           string            `json:"Image"`
	Labels          map[string]string `json:"Labels"`
	Ports           []Port            `json:"Ports"`
	NetworkSettings struct {
		Networks map[string]NetworkEndpoint `json:"Networks"`
	} `json:"NetworkSettings"`
}

// Event is the subset of /events Nexo uses. The payload is only a change
// signal: the watcher re-lists containers instead of trusting event deltas.
type Event struct {
	Type   string `json:"Type"`
	Action string `json:"Action"`
	Actor  struct {
		ID string `json:"ID"`
	} `json:"Actor"`
}

// ListContainers returns the running containers that carry labelKeys.
func (c *Client) ListContainers(ctx context.Context, labelKeys []string) ([]Container, error) {
	filters := map[string][]string{}
	if len(labelKeys) > 0 {
		filters["label"] = labelKeys
	}
	rawFilters, err := json.Marshal(filters)
	if err != nil {
		return nil, fmt.Errorf("encode container filters: %w", err)
	}

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	var containers []Container
	path := "/containers/json?filters=" + url.QueryEscape(string(rawFilters))
	if err := c.get(ctx, path, &containers); err != nil {
		return nil, err
	}
	return containers, nil
}

// Events opens the event stream filtered to container activity. The caller owns
// the returned body and must close it; decoding happens through DecodeEvent.
func (c *Client) Events(ctx context.Context) (io.ReadCloser, error) {
	rawFilters, err := json.Marshal(map[string][]string{"type": {"container"}})
	if err != nil {
		return nil, fmt.Errorf("encode event filters: %w", err)
	}
	resp, err := c.do(ctx, "/events?filters="+url.QueryEscape(string(rawFilters)))
	if err != nil {
		return nil, err
	}
	return resp.Body, nil
}

func (c *Client) get(ctx context.Context, path string, out any) error {
	resp, err := c.do(ctx, path)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if err := json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(out); err != nil {
		return fmt.Errorf("decode %s: %w", path, err)
	}
	return nil
}

func (c *Client) do(ctx context.Context, path string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://docker"+path, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.httpc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("docker api %s: %w", path, err)
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		return nil, fmt.Errorf("docker api %s: %s: %s", path, resp.Status, string(body))
	}
	return resp, nil
}
