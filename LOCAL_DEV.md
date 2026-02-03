# Nexo 本地开发指南

## 快速开始

### 1. 创建本地测试目录和配置

```bash
# 创建测试目录
mkdir -p ~/nexo-dev
cd ~/nexo-dev

# 创建配置文件
cat > config.yaml << 'EOF'
# 基本设置
email: dev@localhost
base_dir: ~/nexo-dev
cert_dir: ~/nexo-dev/certs

# WebUI 端口
webui_port: 8080

# Cloudflare 设置（本地开发可留空，使用自签名证书）
cloudflare:
  api_token: ""

# 代理配置示例
proxies:
  # 示例 1: 反向代理到本地服务
  "app.localhost":
    upstream: http://localhost:3000
  
  # 示例 2: 反向代理到另一个端口
  "api.localhost":
    upstream: http://localhost:8081
  
  # 示例 3: 重定向
  "www.localhost":
    redirect: localhost

  # 示例 4: 代理到 httpbin（用于测试）
  "httpbin.localhost":
    upstream: https://httpbin.org
EOF
```

### 2. 启动 Nexo

```bash
# 使用 sudo 启动（需要绑定 443 端口）
sudo nexo --config ~/nexo-dev/config.yaml

# 或者使用 go run（从源码运行）
cd /path/to/nexo
sudo go run . --config ~/nexo-dev/config.yaml
```

### 3. 访问 WebUI

打开浏览器访问：
- **WebUI**: http://localhost:8080

### 4. 配置本地域名解析

编辑 `/etc/hosts` 文件：

```bash
sudo tee -a /etc/hosts << 'EOF'
127.0.0.1 app.localhost
127.0.0.1 api.localhost
127.0.0.1 www.localhost
127.0.0.1 httpbin.localhost
EOF
```

### 5. 测试代理

启动一个本地测试服务：

```bash
# 使用 Python 启动简单 HTTP 服务器
python3 -m http.server 3000
```

然后访问：
- `https://app.localhost` - 会代理到本地的 3000 端口

**注意**: 由于使用自签名证书，浏览器会显示安全警告，点击"高级" -> "继续访问"。

---

## 配置说明

### 模式 1: 开发模式（自签名证书）

```yaml
cloudflare:
  api_token: ""   # 留空
```

- ✅ 无需真实域名
- ✅ 无需 Cloudflare
- ⚠️ 浏览器会显示证书警告
- ⚠️ 仅适合本地开发测试

### 模式 2: Staging 模式（测试真实域名）

```yaml
staging: true
cloudflare:
  api_token: "your-cloudflare-api-token"
```

- 使用 Let's Encrypt Staging 环境
- 不会触发生产环境的 rate limit
- 证书不会被浏览器信任（测试用）

### 模式 3: 生产模式

```yaml
cloudflare:
  api_token: "your-cloudflare-api-token"
```

- 使用真实的 Let's Encrypt 证书
- 需要真实的域名和 Cloudflare 配置
- 证书被浏览器信任

---

## 完整配置示例

```yaml
# ============================================
# Nexo 配置示例 - 本地开发
# ============================================

# 基本设置
email: your-email@example.com
base_dir: /etc/nexo
cert_dir: /etc/nexo/certs

# WebUI 端口
webui_port: 8080

# 开发模式
staging: false  # 设为 true 使用 Let's Encrypt staging

# Cloudflare 设置
cloudflare:
  api_token: ""  # 生产环境填写真实 token

# 通配符域名
wildcards:
  - "*.example.com"

# 代理配置
proxies:
  # 反向代理
  "api.example.com":
    upstream: http://localhost:8080
  
  "blog.example.com":
    upstream: http://localhost:3000
  
  # 重定向
  "example.com":
    redirect: www.example.com
  
  "github.example.com":
    redirect: github.com/yourusername
```

---

## Docker 运行

```bash
docker run -d \
  --name nexo \
  -p 443:443 \
  -p 8080:8080 \
  -v ~/nexo-dev:/etc/nexo \
  ghcr.io/abcdlsj/nexo:latest
```

---

## 常见问题

### 1. 端口 443 被占用

```bash
# 查找占用 443 的进程
sudo lsof -i :443

# 终止进程
sudo kill -9 <PID>
```

### 2. 证书警告

开发模式下使用自签名证书是正常的，可以：
- 点击浏览器"高级" -> "继续访问"
- 或者将自签名证书添加到系统信任

### 3. 修改 hosts 不生效

```bash
# 刷新 DNS 缓存
sudo dscacheutil -flushcache  # macOS
sudo systemd-resolve --flush-caches  # Linux
```

### 4. WebUI 无法访问

检查防火墙设置：
```bash
# 检查端口是否监听
lsof -i :8080

# 临时关闭防火墙测试（macOS）
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate off
```
