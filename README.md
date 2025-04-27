# Nexo

A simple HTTPS reverse proxy tool with automatic certificate management using Cloudflare DNS challenge.

## Features

- Automatic HTTPS certificate management using Let's Encrypt
- Cloudflare DNS challenge for certificate validation (no need for port 80)
- Support wildcard certificates
- Simple reverse proxy configuration via YAML or CLI
- Command-line interface for proxy management

## Prerequisites

1. Domain(s) managed by Cloudflare
2. Cloudflare API Token with the following permissions:
   - Zone - DNS - Edit
   - Zone - Zone - Read

## Installation

```bash
go install github.com/abcdlsj/nexo@latest
```

## Configuration

Create or edit `~/.nexo/config.yaml`:

```yaml
email: your-email@example.com
cloudflare:
  api_token: "your-cloudflare-api-token"  # Required for DNS challenge
proxies:
  "example.com":
    target: "http://localhost:8080"
  "api.example.com":
    target: "http://localhost:3000"
  "*.test.example.com":
    target: "http://localhost:8888"
```

## Usage

1. Start the server (requires root privileges for port 443):
```bash
sudo nexo server
```

2. Manage proxy configurations:
```bash
# Add a proxy
nexo proxy add --domain example.com --target localhost:8080

# Add a wildcard proxy
nexo proxy add --domain "*.example.com" --target localhost:8080

# List all proxies
nexo proxy list

# Remove a proxy
nexo proxy remove --domain example.com
```

You can also manage proxies by directly editing the config file at `~/.nexo/config.yaml`.

## Example Setup

Let's say you have:
- A React app running on port 3000
- An API server running on port 8080

1. Ensure your domains are configured in Cloudflare and pointing to your server's IP

2. Configure Cloudflare API Token in `~/.nexo/config.yaml`:
```yaml
email: your-email@example.com
cloudflare:
  api_token: "your-cloudflare-api-token"
```

3. Start the server:
```bash
sudo nexo server
```

4. Add proxy configurations:
```bash
nexo proxy add --domain app.example.com --target localhost:3000
nexo proxy add --domain api.example.com --target localhost:8080
```

Now you can access:
- https://app.example.com -> proxied to localhost:3000
- https://api.example.com -> proxied to localhost:8080

## Notes

- Certificates are automatically obtained and renewed
- HTTP requests are automatically redirected to HTTPS
- No need to open port 80 (uses Cloudflare DNS challenge)
- Configuration changes require server restart to take effect

## Troubleshooting

1. Verify domain DNS settings in Cloudflare
2. Check Cloudflare API Token permissions
3. Ensure target services are running
4. Check server logs for errors
5. Verify Cloudflare API Token is correctly configured

## License

MIT 