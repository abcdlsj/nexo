# Nexo

**A small, sharp HTTPS reverse proxy with automatic certificates and a built-in control plane.**

Nexo maps domains to upstream services or HTTPS redirects, obtains certificates through Cloudflare DNS-01, and keeps day-to-day operations visible through a self-contained Web UI.

![Nexo gateway topology and services](docs/assets/nexo-dashboard.png)

## Why Nexo

- **Automatic HTTPS** — individual and wildcard certificates through Let's Encrypt and Cloudflare DNS-01.
- **Simple routing** — reverse proxy or redirect configuration in one YAML file.
- **Container discovery** — one Docker label publishes a route, no config edit.
- **HTTP/1.1 and HTTP/2** — both negotiated over ALPN, with streaming responses left uncapped.
- **Operational UI** — routes, certificate health, traffic telemetry, and security settings.
- **Optional GitHub OAuth** — per-route access control with an explicit user allowlist.
- **Secure defaults** — loopback-only management UI, CSRF protection, login throttling, strict cookies, security headers, and protected secret storage.
- **Single binary** — templates and assets are embedded; no frontend build pipeline or CDN dependency.

## Preview the UI

The preview uses fake in-memory data. It does not read your config, contact Cloudflare, request certificates, write application data, or bind port 443.

```bash
go run . preview
```

Open these pages:

| Page | URL |
| --- | --- |
| Dashboard | <http://127.0.0.1:8088/> |
| Routes | <http://127.0.0.1:8088/proxies> |
| Certificates | <http://127.0.0.1:8088/certs> |
| Traffic | <http://127.0.0.1:8088/traffic> |
| Configuration | <http://127.0.0.1:8088/config> |
| Login | <http://127.0.0.1:8088/login> |
| Not found | <http://127.0.0.1:8088/404> |

Use a different loopback port when needed:

```bash
go run . preview --addr 127.0.0.1:9090
```

Preview mode intentionally refuses non-loopback addresses.

## Quick start

### Requirements

- Go 1.25.12 or newer, or Docker
- A domain managed by Cloudflare
- A Cloudflare API token with `Zone / DNS / Edit` and `Zone / Zone / Read`

### 1. Create a configuration

```yaml
email: ops@example.com
base_dir: /etc/nexo
cert_dir: /etc/nexo/certs

cloudflare:
  api_token: your-cloudflare-api-token

wildcards:
  - "*.example.com"

webui:
  host: 127.0.0.1
  port: "8080"
  username: admin
  password: "$2a$10$replace-with-a-bcrypt-hash"

security:
  rate_limit_enabled: true
  rate_limit_requests: 100
  rate_limit_window: 60
  max_login_attempts: 5
  login_lockout_minutes: 30
  ip_blacklist:
    - 192.0.2.10
    - 2001:db8::/32

proxies:
  api.example.com:
    upstream: http://127.0.0.1:9000

  old.example.com:
    redirect: https://www.example.com
```

Generate the Web UI password hash:

```bash
make password
```

See [`example/config.yaml`](example/config.yaml) for OAuth and additional route examples.

### 2. Start Nexo

```bash
go run . server --config ./config.yaml
```

Nexo serves configured domains on `:443`. The management UI is available at <http://127.0.0.1:8080> by default.

The root command remains an alias for `server`:

```bash
go run . --config ./config.yaml
```

## Docker

```bash
docker build -t nexo .

docker run --rm \
  --name nexo \
  -p 443:443 \
  -p 127.0.0.1:8080:8080 \
  -v /etc/nexo:/etc/nexo \
  nexo server --config /etc/nexo/config.yaml
```

Inside a container, set `webui.host: 0.0.0.0` so the published loopback port can reach the process. Always configure a bcrypt password and keep the Web UI behind a trusted HTTPS gateway, SSH tunnel, or private network.

### Routes from container labels

Let containers declare their own routes instead of editing the config file:

```yaml
docker:
  enabled: true
  socket: /var/run/docker.sock  # default
  host: 127.0.0.1               # prefix used for published host ports
```

The daemon socket must be readable by the Nexo process. Point `docker.socket` at
non-standard paths such as `~/.orbstack/run/docker.sock` or
`~/.colima/default/docker.sock` when the runtime does not use the default.

```bash
docker run --rm --name nexo \
  -p 443:443 -p 127.0.0.1:8080:8080 \
  -v /etc/nexo:/etc/nexo \
  -v /var/run/docker.sock:/var/run/docker.sock \
  nexo server --config /etc/nexo/config.yaml
```

Then one label is enough:

```bash
docker run -d --name api --label nexo.domain=api.example.com my-api:latest
```

| Label | Default | Meaning |
| --- | --- | --- |
| `nexo.domain` | required | Domain(s) to serve; comma-separated for several |
| `nexo.port` | inferred | Container port; inferred when exactly one TCP port is exposed |
| `nexo.upstream` | inferred | Full upstream URL, used verbatim |
| `nexo.network` | first attached | Docker network to read the container IP from |
| `nexo.auth` | `false` | Require GitHub OAuth, like `auth: true` |

The upstream is picked from the first available source: `nexo.upstream`, then the
container IP, then a published host port on `docker.host`, then the container
name (resolvable between containers on the same user-defined network).

- A domain that also exists in `proxies` keeps its config-file definition; the
  container route is skipped and a warning is logged.
- Routes follow the container: `docker stop` removes the route, `docker start`
  restores it, and a changed port or domain is applied without a restart.
- Certificates are obtained the same way as for configured routes, so a
  matching wildcard keeps discovery free of new certificate orders.
- Discovered routes appear read-only in the Web UI.

## Fleet view

One node can observe and operate several Nexo nodes without giving up local
autonomy. Every node stays an independent data plane; the coordinator only polls
a versioned JSON API and relays explicit commands.

```yaml
control_plane:
  enabled: true
  listen: 10.0.0.11:9090        # tailnet/VPN address for remote peers
  node:
    name: nexo-main-01
  auth:
    token_file: /etc/nexo/control-token        # read:control
    write_token_file: /etc/nexo/control-write  # commands
  coordinator:
    enabled: true
    peers:
      - id: nexo-hk-01
        url: http://10.0.0.12:9090
        token_file: /etc/nexo/peers/nexo-hk-01.read
        write_token_file: /etc/nexo/peers/nexo-hk-01.write
```

- The coordinator pulls each peer on `poll_interval` (default 10s). Peers never
  need an inbound rule beyond the control listener, and no peer stores the
  coordinates of another.
- Use the tailnet/VPN address for every peer (`100.64.0.0/10`, RFC 1918, ULA).
  Plaintext HTTP is accepted only for those addresses. A public address needs
  HTTPS; a plaintext URL to a public host is refused unless
  `allow_insecure_http` is set explicitly.
- A peer that stops answering is shown `stale` after `stale_after`, then
  `offline` after three failed polls. A peer id mismatch is reported separately
  instead of being counted as healthy.
- The process refuses to start when a listener is public without TLS, or when a
  public listener has no token, or when a token file is not `0600`. Never reuse
  the data-plane `:443` listener.
- Tokens are re-read per request, so rotation needs no restart. Keep read and
  write tokens separate: a monitoring credential cannot mutate configuration.
- Commands require `Content-Type: application/json`, which forces a CORS
  preflight and blocks cross-site form posts against a loopback listener.
- The node id is generated once and persisted to `<base_dir>/node-id`.

Machine API (`/control/v1`, bearer token, JSON):

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/healthz` | liveness, no authentication |
| GET | `/node` | identity, version, config digest |
| GET | `/capabilities` | resources, features, limits |
| GET | `/snapshot?include=…&recent_limit=…` | one consistent node snapshot |
| GET | `/resources/{kind}[/{id}]` | routes, certificates, traffic, security, links |
| GET | `/fleet/snapshot` | coordinator view (local + peers + warnings) |
| POST | `/commands` | apply `route.upsert`, `route.delete`, `certificate.renew`, `security.update`; add `target_node_id` to forward through a coordinator |

The snapshot never carries API tokens, passwords, key material or upstream
paths. Traffic aggregates are per node; unique IP counts are explicitly not
summed across the fleet, and recent records ship a hashed IP without path or
user agent.

### Reaching a node beyond the tailnet

If a node is only reachable over the public internet, terminate TLS on the
control listener and trust a private CA rather than the public one:

```yaml
control_plane:
  enabled: true
  listen: 0.0.0.0:9090
  tls:
    cert_file: /etc/nexo/control.crt
    key_file: /etc/nexo/control.key
    client_ca_file: /etc/nexo/control-ca.crt   # optional mutual TLS
  auth:
    token_file: /etc/nexo/control-token
    write_token_file: /etc/nexo/control-write

  coordinator:
    peers:
      - id: nexo-hk-01
        url: https://nexo-hk-01.example.com:9090
        ca_file: /etc/nexo/peers/control-ca.crt
        client_cert_file: /etc/nexo/peers/nexo-main-01.crt
        client_key_file: /etc/nexo/peers/nexo-main-01.key
        server_name: nexo-hk-01.example.com
        token_file: /etc/nexo/peers/nexo-hk-01.read
        write_token_file: /etc/nexo/peers/nexo-hk-01.write
```

`client_ca_file` on the listener turns on mutual TLS: a peer must present a
client certificate signed by that CA *and* a valid bearer token. Peer
certificates are optional on the tailnet, where WireGuard already authenticates
both ends.

### Making changes from the fleet panel

The Fleet page (`/fleet`) renders the node graph, a merged route table,
certificate state and warnings such as a host served by two nodes. Editing a
route or policy sends a command to the owning node, which applies it through the
same serialized config writer as its local Web UI (atomic write, fsnotify
reload, rollback on failure).

Every command carries `if_match` with the target node's `config_hash`. If the
node changed in the meantime the write is rejected with `409 conflict` instead
of overwriting a local edit. Each attempt is appended to
`<base_dir>/control-audit.jsonl`, and `IdempotencyKey` makes a retried request
safe.

Raw YAML editing is intentionally not exposed through the control plane.

## Routing

### Reverse proxy

```yaml
proxies:
  app.example.com:
    upstream: http://127.0.0.1:3000
```

Streaming routes (SSE, long-lived responses) work out of the box because Nexo
does not cap the total response write time by default. Optional per-route
timeouts are available for routes that need them:

```yaml
proxies:
  api.example.com:
    upstream: http://127.0.0.1:3000
    # write_timeout: "2m"             # total response write cap; empty/"0" = unlimited
    # response_header_timeout: "30s"  # wait for upstream headers; "0" = wait indefinitely
    # retry: true                     # retry once on pre-response errors (GET/HEAD/OPTIONS only)
```

- `write_timeout` and `response_header_timeout` accept Go duration strings
  (e.g. `5m`, `30s`). A global `write_timeout` or `response_header_timeout` at
  the top level applies to all routes unless a route overrides it.
  `write_timeout` defaults to disabled; `response_header_timeout` defaults to
  30s when neither is configured, and `"0"` waits indefinitely.
- `retry` is opt-in and safe by construction: it retries only idempotent
  methods and never re-sends POST/PUT/PATCH bodies.
- Avoid `write_timeout` on WebSocket routes; a total write cap is incompatible
  with hijacked long-lived connections.

### Request limits

`max_request_body` caps the request body size accepted from clients, for every
route. It accepts byte sizes such as `10MB`, `512KB`, or a raw byte count, and
defaults to 10MB. Raise it when the upstream accepts larger uploads:

```yaml
max_request_body: 100MB
```

`read_timeout` caps how long Nexo takes to read a complete request (headers
plus body); it defaults to `30s`. A large upload on a slow link takes longer
than 30s to arrive, so widen the window together with the body limit:

```yaml
read_timeout: 10m
```

### OAuth path exclusions

Routes with `auth: true` normally protect every path. `auth_exclude` keeps
selected paths public, which is required for PWA assets (manifest, icons) that
browsers fetch without a session:

```yaml
proxies:
  app.example.com:
    upstream: http://127.0.0.1:3000
    auth: true
    auth_exclude:
      - /manifest.webmanifest
      - /favicon.ico
      - /apple-touch-icon.png
      - /icon-*.png
```

- Each entry must start with `/`. Without a wildcard it must match the request
  path exactly; `*` matches any run of characters (e.g. `/icon-*.png`).
- Excluded requests are proxied without OAuth and do not carry `X-Auth-User`.
- The same list can be edited per route in the Web UI under **Auth exclusions**.


### Tunneled upstreams (gnar)

Nexo injects a sensible `Cache-Control` when the upstream omits one. Tunnel
traffic is dynamic and can legitimately take a long time before the first
response headers arrive, so routes fronting gnar should both widen the header
timeout and leave response headers untouched:

```yaml
response_header_timeout: 300s

proxies:
  tunnel.example.com:
    upstream: http://127.0.0.1:8080
    cache: false
```

`cache` defaults to `true`, preserving the historical behavior. Setting it to
`false` disables automatic `Cache-Control` injection for that route and passes
upstream response headers through unchanged. `response_header_timeout` here is
the global default; the route can still override it with its own
`response_header_timeout`, including `"0"` for an unlimited wait.

### HTTPS redirect

```yaml
proxies:
  old.example.com:
    redirect: https://www.example.com
```

### Gateway directory metadata (optional)

Nexo publishes proxy routes in the gateway directory without additional configuration. It probes the configured upstream, classifies HTML applications and JSON/OpenAPI services, and discovers standard HTML icon links. Discovery results are cached. If no icon is found, the route uses the first letter of its display name. Connection failures, timeouts, and 5xx responses add a small red availability marker.

Redirects and registrable apex domains are not published by default. Add a `portal` block to publish one explicitly.

Use `portal` when a route needs custom presentation, ordering, visibility, or an explicit service kind:

```yaml
proxies:
  studio.example.com:
    upstream: http://127.0.0.1:4173
    portal:
      name: Studio
      description: Content, assets and publishing
      icon: auto
      kind: website
      group: workspace
      order: 10
      hidden: false
```

`icon` accepts `auto`, a root-relative path, or an HTTP(S) URL. `kind` accepts `website`, `api`, or `service`; omit it to use automatic detection. Set `hidden: true` to keep a route active without listing it on the gateway dashboard.

### GitHub OAuth protection

```yaml
auth:
  auth_host: auth.example.com
  secret_key: "" # generated on first start
  session_ttl: 24h
  github:
    client_id: your-client-id
    client_secret: your-client-secret
    allowed_users:
      - your-github-username

proxies:
  admin.example.com:
    upstream: http://127.0.0.1:9001
    auth: true
```

`allowed_users` is fail-closed: an empty list allows nobody.

## Security model

- The Web UI binds to `127.0.0.1` unless explicitly configured otherwise.
- A passwordless Web UI is forced back to loopback even if a public bind address is configured.
- Config files containing API tokens and OAuth secrets are atomically written with mode `0600`.
- State-changing Web UI actions require POST and a CSRF token.
- Session cookies are HTTP-only, strict same-site, and secure when served through HTTPS.
- OAuth redirects must use HTTPS and match a configured host.
- IP throttling and blacklists use the actual peer address; untrusted forwarding headers are ignored.
- Dynamic, authenticated, and cookie-setting upstream responses are never changed into public-cacheable responses.

If you expose the Web UI beyond localhost, terminate HTTPS at a trusted gateway and restrict network access. A password over public plain HTTP is still a password sent over public plain HTTP—do not do that.

## Development

```bash
# Run tests
go test ./...

# Include the race detector
go test -race ./...

# Static checks
go vet ./...

# Build
go build ./...

# Vulnerability scan
go run golang.org/x/vuln/cmd/govulncheck@latest ./...
```

For local domain and certificate testing, see [`LOCAL_DEV.md`](LOCAL_DEV.md).

## Project layout

```text
.
├── internal/server/   HTTPS listener, reloads, routing orchestration
├── internal/webui/    management handlers, templates, fake-data preview
├── pkg/auth/          GitHub OAuth and signed sessions
├── pkg/cert/          ACME and certificate storage
├── pkg/config/        YAML configuration
├── pkg/proxy/         reverse proxy and cache policy
└── pkg/traffic/       bounded traffic telemetry and persistence
```

## License

MIT
