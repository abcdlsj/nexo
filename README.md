# Nexo

A simple HTTPS reverse proxy with automatic certificate management using Cloudflare DNS challenge.

## Features

- Automatic HTTPS certificate management using Let's Encrypt
- Cloudflare DNS challenge for certificate validation (no need for port 80)
- Smart wildcard certificate management
- Support for both proxy and redirect configurations
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

# Cloudflare settings
cloudflare:
  api_token: your-cloudflare-api-token    # Required for DNS challenge

# Wildcard certificate domains
wildcards:
  - "*.example.com"    # Will obtain *.example.com certificate
  - "*.yourdomain.com" # Will obtain *.yourdomain.com certificate

# Proxy configurations
proxies:
  # Proxy to upstream server
  "api.example.com":
    upstream: http://localhost:8080
  
  # Redirect to another domain
  "example.com":
    redirect: www.example.com  # Will redirect to https://www.example.com
  
  # Proxy with wildcard certificate
  "blog.example.com":
    upstream: http://localhost:3000
  
  # Redirect to external site
  "github.example.com":
    redirect: github.com/yourusername  # Will redirect to https://github.com/yourusername
```

### Configuration Explanation

1. **Basic Settings**
   - `base_dir`: Directory for configuration files
   - `cert_dir`: Directory for storing certificates
   - `email`: Your email for Let's Encrypt
   - `cloudflare.api_token`: Your Cloudflare API token

2. **Certificate Management**
   - List domains in `wildcards` section to obtain wildcard certificates
   - Other domains in `proxies` will get individual certificates automatically
   - Certificates are automatically renewed 30 days before expiration

3. **Proxy Settings**
   Each entry under `proxies` can be configured as either:
   - A proxy to an upstream server using `upstream`
   - A redirect to another domain using `redirect`
   - Domains matching wildcard certificates will use them automatically

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
- Redirects automatically add https:// if not specified

## Project Structure

```
nexo/
├── internal/
│   └── server/      # Core server implementation
└── pkg/
    ├── cert/        # Certificate management
    ├── config/      # Configuration handling
    └── proxy/       # Proxy and redirect handling
```

## Troubleshooting

1. Verify domain DNS settings in Cloudflare
2. Check Cloudflare API Token permissions
3. Ensure upstream services are running
4. Check server logs for errors
5. Verify configuration file syntax

## Others

```
# 制 HTTPS 连接频率（每分钟最多20个新连接）
iptables -A INPUT -p tcp --dport 443 -m state --state NEW -m recent --set --name https_conn
iptables -A INPUT -p tcp --dport 443 -m state --state NEW -m recent --update --seconds 60 --hitcount 20 --name https_conn -j DROP

# 限制每个IP的并发连接数（最多10个）
iptables -A INPUT -p tcp --dport 443 -m connlimit --connlimit-above 10 -j DROP

# 防止 SYN flood 攻击
iptables -A INPUT -p tcp --dport 443 -m state --state NEW -m limit --limit 2/s --limit-burst 5 -j ACCEPT

# 允许正常的 HTTPS 流量
iptables -A INPUT -p tcp --dport 443 -m state --state NEW -j ACCEPT
```

## License

MIT 