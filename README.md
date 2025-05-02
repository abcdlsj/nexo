# Nexo

A simple HTTPS reverse proxy with automatic certificate management using Cloudflare DNS challenge.

## Features

- Automatic HTTPS certificate management using Let's Encrypt
- Cloudflare DNS challenge for certificate validation (no need for port 80)
- Smart wildcard certificate management
- Automatic certificate renewal (30 days before expiration)
- Dynamic configuration through YAML
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
# Basic settings
base_dir: /etc/nexo          # Default config directory
cert_dir: /etc/nexo/certs    # Default certificate directory
email: your-email@example.com
cloudflare:
  api_token: your-cloudflare-api-token    # Required for DNS challenge

# Wildcard certificate domains
domains:
  - example.com                # Will obtain *.example.com certificate
  - yourdomain.com            # Will obtain *.yourdomain.com certificate

# Proxy configurations
proxies:
  # Using wildcard certificate from example.com
  blog.example.com:
    upstream: http://localhost:3000
  api.example.com:
    upstream: http://localhost:8080

  # Using wildcard certificate from yourdomain.com
  dev.yourdomain.com:
    upstream: http://localhost:3001

  # Will obtain a separate certificate
  specific.otherdomain.com:
    upstream: http://localhost:5000
```

### Configuration Explanation

1. **Basic Settings**
   - `base_dir`: Directory for configuration files
   - `cert_dir`: Directory for storing certificates
   - `email`: Your email for Let's Encrypt
   - `cloudflare.api_token`: Your Cloudflare API token

2. **Certificate Management**
   - List domains in `domains` section to use wildcard certificates
   - Domains not listed will get individual certificates
   - Certificates are automatically renewed 30 days before expiration

3. **Proxy Settings**
   - Each entry under `proxies` maps a domain to an upstream server
   - Wildcard certificates are automatically used for matching domains
   - Other domains get individual certificates

## Usage

Start the server (requires root privileges for port 443):
```bash
sudo nexo server
```

## Notes

- Certificates are automatically obtained and renewed
- Configuration changes are detected and applied automatically
- No need to open port 80 (uses Cloudflare DNS challenge)
- Supports both system-wide (/etc/nexo) and user-specific (~/.nexo) configuration

## Troubleshooting

1. Verify domain DNS settings in Cloudflare
2. Check Cloudflare API Token permissions
3. Ensure upstream services are running
4. Check server logs for errors
5. Verify configuration file syntax and permissions

## License

MIT 