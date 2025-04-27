# Nexo

A simple HTTPS reverse proxy tool with automatic certificate management using Cloudflare DNS challenge.

## Features

- Automatic HTTPS certificate management using Let's Encrypt
- Cloudflare DNS challenge for certificate validation (no need for port 80)
- Support wildcard certificates
- Dynamic configuration through YAML file
- Automatic certificate renewal
- Docker support

## Prerequisites

1. Domain(s) managed by Cloudflare
2. Cloudflare API Token with the following permissions:
   - Zone - DNS - Edit
   - Zone - Zone - Read

## Installation

### Using Docker

```bash
docker pull ghcr.io/abcdlsj/nexo:latest

# Create config directory
mkdir -p /etc/nexo

# Create or edit config file
vim /etc/nexo/config.yaml

# Run the container
docker run -d \
  --name nexo \
  -p 443:443 \
  -v /etc/nexo:/etc/nexo \
  ghcr.io/abcdlsj/nexo:latest
```

### Manual Installation

```bash
go install github.com/abcdlsj/nexo@latest
```

## Configuration

Create or edit `/etc/nexo/config.yaml` (or `~/.nexo/config.yaml` for non-root users):

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

The configuration file is watched for changes and will be automatically reloaded when modified.

## Usage

1. Start the server (requires root privileges for port 443):
```bash
sudo nexo server
```

## Example Setup

Let's say you have:
- A React app running on port 3000
- An API server running on port 8080

1. Ensure your domains are configured in Cloudflare and pointing to your server's IP

2. Configure in `/etc/nexo/config.yaml`:
```yaml
email: your-email@example.com
cloudflare:
  api_token: "your-cloudflare-api-token"
proxies:
  "app.example.com":
    target: "http://localhost:3000"
  "api.example.com":
    target: "http://localhost:8080"
```

3. Start the server:
```bash
sudo nexo server
```

Now you can access:
- https://app.example.com -> proxied to localhost:3000
- https://api.example.com -> proxied to localhost:8080

## Notes

- Certificates are automatically obtained and renewed
- Configuration changes are detected and applied automatically
- No need to open port 80 (uses Cloudflare DNS challenge)
- Supports both system-wide (/etc/nexo) and user-specific (~/.nexo) configuration

## Troubleshooting

1. Verify domain DNS settings in Cloudflare
2. Check Cloudflare API Token permissions
3. Ensure target services are running
4. Check server logs for errors
5. Verify Cloudflare API Token is correctly configured
6. Check the configuration file permissions

## License

MIT 