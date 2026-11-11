# RFC 0001：Nexo 多节点控制面与链路视图

- 状态：Implemented（Phase 1–3；写操作以显式命令 API 落地，见 README「Fleet」）
- 作者：Nexo maintainers
- 日期：2026-08-21
- 目标版本：Control API v1

## 摘要

Nexo 当前是单机自治的反向代理：路由、证书和流量数据都由本机持有。本文设计一个只通过 HTTP 暴露的控制面，使一台 Nexo 可以登记并观察其他 Nexo，统一查看节点状态、路由、证书、流量和跨节点数据链路。

本 RFC 的核心选择是：

1. 每台 Nexo 都是独立的数据面节点；控制面不接管转发、证书签发或业务配置。
2. 任意一台 Nexo 都可以开启协调器（coordinator）角色，主动拉取其登记的节点。
3. 节点间使用版本化、资源化的 JSON API；第一版只读，后续可在同一资源模型上增加变更命令。
4. 链路使用显式 `link` 资源表达，同时保留从路由目标推导链路的能力；不依赖模糊的域名猜测。
5. 聚合结果带来源、时间和新鲜度，离线节点不会被静默当成正常节点。

## 1. 背景与问题

典型部署是：

~~~text
浏览器 ──> Nexo A ──> 服务 A
                 └──> Nexo B ──> 服务 B
~~~

现在用户只能分别打开 A、B 的 Web UI。这样会产生四个问题：

- 看不到节点是否在线、版本是否一致；
- 无法在一张图上看到 `Nexo A -> Nexo B -> upstream`；
- 流量、路由和证书需要逐台核对；
- 将来若增加告警、健康检查或远程运维，缺少稳定的机器接口。

现有 Web UI API 依赖浏览器会话和本机上下文，不适合作为节点协议。因此控制面必须独立于 Web UI，具有自己的认证、版本和数据模型。

## 2. 目标

### 2.1 必须满足

- 任意 Nexo 可作为被观察节点。
- 任意 Nexo 可作为协调器；不依赖外部中心服务或数据库。
- 通过 HTTP 提供机器可读 API。
- 在一次快照中表达节点、路由、证书、流量摘要和链路。
- 节点故障、超时和数据过期可见且可区分。
- API 可增加新资源、新字段和新能力，不破坏旧客户端。
- 第一版不允许远程修改路由、证书、密钥或系统配置。

### 2.2 非目标

- 不把多台 Nexo 变成共享配置中心。
- 不复制证书私钥、Cloudflare Token、OAuth Secret 或 Web UI 密码。
- 不承诺跨节点的强一致实时流量统计。
- 不在控制面内承载业务请求或代理业务流量。
- 不在第一版实现跨公网的零信任组网；公网场景应先使用 VPN、内网穿透或可信反向代理。

## 3. 术语与角色

| 术语 | 含义 |
| --- | --- |
| 节点（node） | 运行一个 Nexo 进程、拥有唯一 `node_id` 的实例。 |
| 数据面（data plane） | 监听业务端口、转发 HTTP/HTTPS 请求的部分。 |
| 控制面（control plane） | 暴露状态、能力和拓扑资源的 HTTP API。 |
| 被观察节点（agent） | 提供本地资源快照的 Nexo。所有节点默认都是 agent。 |
| 协调器（coordinator） | 配置了 peers、主动拉取其他 agent 并提供联邦视图的 Nexo。 |
| peer | 协调器配置中的一个远端 agent。 |
| 资源（resource） | 具有 `kind`、`id`、`spec`、`status` 的可演进对象。 |
| 快照（snapshot） | 某个时间点对一组资源的一致只读视图。 |
| 链路（link） | 两个资源之间的有向数据面关系，例如一个 route 指向另一个节点的 route。 |

## 4. 总体架构

~~~text
                     ┌────────────────────────────┐
                     │ 浏览器 / CLI / 告警系统      │
                     └──────────────┬─────────────┘
                                    │ HTTP（本机协调器）
                     ┌──────────────▼─────────────┐
                     │ Nexo A：协调器 + 数据面     │
                     │  本地快照 / 联邦缓存 / 聚合   │
                     └───────┬───────────┬────────┘
                             │ HTTP       │ HTTP
                       ┌─────▼────┐ ┌────▼─────┐
                       │ Nexo B   │ │ Nexo C   │
                       │ agent    │ │ agent    │
                       └──────────┘ └──────────┘
~~~

### 4.1 数据方向

- agent 不主动向 coordinator 推送业务流量。
- coordinator 按 `poll_interval` 并发拉取 agent 快照。
- agent 只返回本机数据；不会递归拉取自己的 peers。
- coordinator 将远端快照放入内存缓存，缓存与本机 `traffic.json` 分离。
- Web UI 只访问本机协调器的本地控制 API，不直接持有每个 peer 的凭据。

这样可以工作在 NAT 后面：只需协调器能访问 agent 的控制端口。若网络方向相反，未来增加 push/relay 能力，不改变资源模型。

### 4.2 控制端口隔离

控制面使用独立监听地址，不复用业务 `:443`，也不与现有 Web UI 端口混用。默认只监听回环地址；配置为非回环地址时必须同时配置认证令牌，启动时拒绝不安全组合。

## 5. 配置模型

顶层增加 `control_plane`，不改变现有 `webui`、`proxies` 和 `traffic` 配置。

~~~yaml
control_plane:
  enabled: true
  listen: 127.0.0.1:9090

  node:
    id: nexo-main-01
    name: Main Gateway
    labels:
      region: sh
      environment: prod

  auth:
    mode: bearer
    token_file: /etc/nexo/control-token

  coordinator:
    enabled: true
    poll_interval: 10s
    request_timeout: 3s
    stale_after: 30s
    peers:
      - id: nexo-hk-01
        name: Hong Kong Gateway
        url: http://10.0.0.12:9090
        token_file: /etc/nexo/peers/nexo-hk-01.token
        tls:
          insecure_skip_verify: false
      - id: nexo-bj-01
        url: http://10.0.0.13:9090
        token_file: /etc/nexo/peers/nexo-bj-01.token

  topology:
    links:
      - id: public-api-to-hk
        from:
          node_id: nexo-main-01
          route_id: public-api
        to:
          node_id: nexo-hk-01
          route_id: internal-api
        relation: forwards
        labels:
          purpose: regional-failover
~~~

### 5.1 节点身份

- `node.id` 是逻辑身份，必须在一个控制域内唯一；建议使用安装时生成的 UUID 或稳定主机名。
- `node.name` 仅用于展示，可以修改。
- `labels` 用于筛选和未来的策略，不参与身份判断。
- 若省略 `node.id`，首次启动生成并写入 `base_dir/node-id`；不会根据 IP 生成，避免 DHCP 变化造成节点漂移。

### 5.2 peer 约束

- `peers[].id` 必须与对端返回的 `node.id` 一致，否则标记为 `identity_mismatch`，不纳入健康视图。
- 每个 peer 使用独立令牌；协调器配置不能使用一个全局共享令牌。
- `url` 只允许 `http` 或 `https`，禁止 URL 中携带用户名、密码或令牌。
- peer 列表只在协调器本地生效，不下发给远端。

### 5.3 链路表达

链路优先使用稳定的 `route_id`，不使用展示名称。现有 `proxies` 配置迁移时，为每个域名生成稳定 ID 并写入路由资源。

若不能修改业务路由配置，可仅配置 `topology.links`。若能修改路由，推荐在 route 的 backend 上显式引用：

~~~yaml
proxies:
  api.example.com:
    id: public-api
    upstream: https://hk.internal.example.com
    backend_ref:
      node_id: nexo-hk-01
      route_id: internal-api
~~~

`backend_ref` 只描述拓扑关系；是否真的通过远端 Nexo 转发，仍由现有 `upstream` 决定。这样控制面不会偷偷改变数据面行为。

## 6. API 约定

### 6.1 基本规则

- Base URL：`/control/v1`。
- 媒体类型：`application/json`。
- 时间统一使用 RFC 3339 UTC。
- JSON 字段使用 `snake_case`。
- 客户端必须忽略未知字段和未知资源类型。
- 所有响应带 `X-Request-Id`；请求可传同名请求头。
- 快照支持 `ETag` 和 `If-None-Match`。
- 服务端限制响应大小、查询数量和最近请求记录条数。

### 6.2 通用响应封套

~~~json
{
  "api_version": "control.nexo.io/v1",
  "kind": "Snapshot",
  "meta": {
    "request_id": "01J...",
    "resource_version": "node-seq-1842",
    "generated_at": "2026-08-21T10:00:00Z",
    "observed_at": "2026-08-21T09:59:59.812Z"
  },
  "data": {}
}
~~~

错误统一为：

~~~json
{
  "api_version": "control.nexo.io/v1",
  "kind": "Error",
  "error": {
    "code": "invalid_request",
    "message": "include contains an unsupported resource",
    "retryable": false,
    "details": {}
  }
}
~~~

`message` 供人读，客户端只依赖稳定的 `code` 和 `retryable`。

### 6.3 端点

| 方法 | 路径 | 用途 |
| --- | --- | --- |
| GET | `/control/v1/healthz` | 进程存活检查，不返回敏感信息。 |
| GET | `/control/v1/node` | 本机身份、版本、启动时间和运行状态。 |
| GET | `/control/v1/capabilities` | 本机支持的资源、字段和可选特性。 |
| GET | `/control/v1/snapshot` | 本机一致快照。默认不含最近请求明细。 |
| GET | `/control/v1/resources/{kind}` | 分页读取单类资源。 |
| GET | `/control/v1/resources/{kind}/{id}` | 读取单个资源。 |
| GET | `/control/v1/fleet/snapshot` | 仅协调器提供的联邦快照。 |
| GET | `/control/v1/fleet/nodes` | 协调器缓存的节点状态列表。 |
| GET | `/control/v1/fleet/links` | 合并后的跨节点链路。 |

第一版只实现表中 GET 端点。未来写操作统一放在 `/control/v1/commands`，不复用资源 GET/PUT，避免把查询接口悄然变成高风险管理接口。

### 6.4 快照查询参数

~~~text
/control/v1/snapshot?
  include=node,routes,certificates,traffic,links&
  recent_limit=50
~~~

- `include` 默认 `node,routes,certificates,traffic,links`。
- `recent_limit` 默认 0，最大 200；聚合统计与最近请求分开控制。
- 不识别的 `include` 返回 `invalid_request`，不静默忽略拼写错误。
- `/fleet/snapshot` 额外支持 `node_ids`、`labels`、`freshness=all|fresh|stale`。

## 7. 资源模型

所有资源采用以下形状：

~~~json
{
  "api_version": "control.nexo.io/v1",
  "kind": "Route",
  "metadata": {
    "id": "public-api",
    "node_id": "nexo-main-01",
    "resource_version": "42",
    "updated_at": "2026-08-21T09:58:00Z",
    "labels": {"team": "platform"}
  },
  "spec": {},
  "status": {}
}
~~~

### 7.1 Node

`spec`：`id`、`name`、`version`、`build`、`labels`、`endpoints`。

`status`：`phase`（`running|degraded|stopping`）、`started_at`、`last_reload_at`、`config_hash`。

不返回配置原文、环境变量、命令行参数和文件路径。

### 7.2 Route

`spec`：`route_id`、`host`、`kind`、`backend`、`auth_required`、`enabled`。

`backend` 支持：

- `http`：仅返回规范化后的 scheme、host、port；默认不返回完整 URL 中的路径和凭据。
- `redirect`：返回目标主机，敏感查询参数必须被剥离。
- `node_route`：返回 `node_id` 和 `route_id`，用于显式拓扑。
- 扩展类型通过 `backend.kind` 命名空间扩展，例如 `vendor.example/tunnel`。

`status`：`healthy|unavailable|unknown`、最近探测时间、错误码和请求摘要。

### 7.3 Certificate

`spec`：域名、是否 wildcard、issuer。

`status`：`valid|expiring|expired|missing|unknown`、`not_after`、剩余天数。

绝不返回证书 PEM、私钥、ACME 账户密钥或 Cloudflare 配置。

### 7.4 TrafficSummary

~~~json
{
  "total_requests": 1234,
  "https_requests": 1230,
  "unique_ip_count": 86,
  "domains": [
    {"route_id":"public-api","requests":900,"https_requests":898,"unique_ip_count":64}
  ],
  "recent_records": []
}
~~~

最近记录必须增加 `node_id`，并按配置脱敏 IP、User-Agent 和路径。默认不跨节点发送完整 IP；可配置为哈希或完全省略。

### 7.5 Link

~~~json
{
  "kind": "Link",
  "metadata": {"id":"public-api-to-hk","node_id":"nexo-main-01"},
  "spec": {
    "from": {"node_id":"nexo-main-01","route_id":"public-api"},
    "to": {"node_id":"nexo-hk-01","route_id":"internal-api"},
    "relation": "forwards",
    "source": "explicit"
  },
  "status": {
    "state": "connected",
    "last_observed_at": "2026-08-21T10:00:00Z"
  }
}
~~~

`source` 取 `explicit|inferred|discovered`。推导链路只能作为辅助展示，不能覆盖显式链路。

## 8. 联邦快照与聚合语义

协调器为每个 peer 保存一份 `PeerSnapshot`：

~~~json
{
  "node_id": "nexo-hk-01",
  "state": "fresh",
  "last_success_at": "2026-08-21T10:00:00Z",
  "latency_ms": 42,
  "snapshot": {},
  "error": null
}
~~~

状态定义：

- `fresh`：最近成功时间不超过 `stale_after`。
- `stale`：超过 `stale_after`，但仍保留最后成功快照。
- `offline`：连续失败达到 3 次，快照仍可查看但不能计入“在线节点”。
- `identity_mismatch`：URL 返回的 `node.id` 与配置不符。

聚合规则：

| 数据 | 联邦处理 |
| --- | --- |
| 请求总数、HTTPS 请求数 | 可按节点求和，并标注统计时间窗。 |
| 路由数、证书数 | 可求和；重复资源按 `node_id + id` 区分。 |
| 最近请求 | 合并排序，保留来源 `node_id`，限制总条数。 |
| Unique IP | 默认按节点分别展示；不直接相加。 |
| 延迟、P95、错误率 | 分节点展示；不得对百分位数简单平均。 |
| stale/offline 节点 | 默认不进入“健康总数”，但继续显示。 |

联邦快照必须带 `aggregation_warnings`，例如 `partial_data`、`stale_peers`、`non_additive_metric`。前端不能只显示一个看似精确的总数。

## 9. 链路发现与展示

链路解析按以下优先级：

1. `topology.links` 显式声明；
2. route 的 `backend_ref` 显式声明；
3. 若开启 `inference.enabled`，根据 upstream 主机、端口和受信任的节点 endpoint 推导；
4. 无法确认时显示为外部目标，不猜测。

图算法以 `node_id/route_id` 为顶点，以 `Link` 为有向边。展示层需要：

- 标出入口节点、终点服务、跨节点边；
- 在边上显示最近流量、延迟和状态；
- 对环路使用 `cycle_detected` 标记，不递归展开；
- 对未知目标显示虚线节点；
- 支持按节点、标签、域名和状态过滤。

控制面只描述关系，不保证关系一定可达。可达性由 route health 或未来的 probe 资源报告。

## 10. 认证、授权与网络安全

### 10.1 v1 认证

- 请求使用 `Authorization: Bearer <token>`。
- 令牌从文件读取，权限建议 `0600`；日志、错误和快照中不得回显。
- 每个 peer 独立令牌，服务端使用常量时间比较。
- 支持 `X-Nexo-Node-Id` 作为审计信息，但不能代替令牌认证。
- 认证失败统一返回 `401`，不泄露节点是否存在。

### 10.2 HTTP 使用边界

HTTP 明文只允许在受控私网、localhost、VPN 或已加密的隧道中使用。生产环境推荐 `https`；配置 `tls` 时支持 CA、客户端证书和服务器名称校验。`insecure_skip_verify` 仅允许显式开发配置，并在启动日志中告警。

### 10.3 授权

v1 只有 `read:control` 权限。令牌模型预留权限字段：

~~~yaml
auth:
  tokens:
    - id: dashboard
      token_file: /etc/nexo/control-token
      scopes: [read:control]
~~~

未来写操作至少需要 `write:routes`、`write:certificates`、`admin:control` 等独立 scope，并要求审计记录和幂等键。

### 10.4 数据最小化

默认只返回聚合数据。IP、User-Agent、路径属于高敏感字段，分别支持 `full|hash|redact` 三种策略；跨节点默认 `hash` 或 `redact`。任何资源都不能返回密钥、密码、令牌、私钥和原始配置文件。

## 11. 可靠性、限流与资源保护

- coordinator 对每个 peer 使用独立 HTTP client、连接池和超时。
- 拉取使用指数退避和随机抖动；失败不阻塞其他 peer。
- agent 对每个来源 IP、令牌和全局并发数限流。
- `snapshot` 生成使用读锁下的不可变副本，避免阻塞数据面。
- `recent_records` 有硬上限；响应体超过限制返回 `response_too_large`。
- coordinator 重启后可丢弃联邦缓存；不得把过期数据伪装成新数据。
- 采用 `ETag` 后，未变化快照返回 `304 Not Modified`。

## 12. 可扩展性与兼容策略

### 12.1 版本

- URL 主版本为 `/control/v1`；v1 内禁止删除字段或改变字段含义。
- 破坏性变更进入 `/control/v2`，允许 v1、v2 并存一段时间。
- `api_version` 使用 `control.nexo.io/v1`，`kind` 使用 PascalCase。

### 12.2 Capability negotiation

`GET /capabilities` 返回：

~~~json
{
  "api_version": "control.nexo.io/v1",
  "resources": ["Node","Route","Certificate","TrafficSummary","Link"],
  "features": ["etag","redacted_traffic","fleet_snapshot"],
  "limits": {"max_recent_limit": 200}
}
~~~

客户端按能力选择请求，不按版本号猜功能。协调器发现 peer 不支持某资源时，只将其标为 `unsupported`，不让整个快照失败。

### 12.3 扩展字段

- 兼容新增字段放在 `spec` 或 `status` 中，旧客户端忽略。
- 厂商或插件字段放在 `extensions` 下，键使用反向域名命名空间，例如 `com.example/metrics`。
- 新指标不修改 `TrafficSummary` 的既有语义，而是增加 `Metric` 资源。
- 插件不能直接注册任意 HTTP 路由；必须通过受控资源注册表暴露。

### 12.4 未来 watch 与命令

轮询是 v1 默认机制。后续可增加：

- `GET /control/v1/watch?resource=Route`：SSE 增量事件；
- `POST /control/v1/commands`：异步命令，返回 `command_id`；
- `GET /control/v1/commands/{id}`：命令状态和审计结果。

这些扩展复用 `resource_version`、`kind`、`status` 和错误封套，不另造一套协议。

## 13. 可观测性

控制面自身输出以下指标和结构化日志：

- `nexo_control_requests_total{endpoint,status}`；
- `nexo_control_request_duration_seconds{endpoint}`；
- `nexo_control_peer_state{peer,state}`；
- `nexo_control_peer_latency_seconds{peer}`；
- `nexo_control_snapshot_age_seconds{node}`；
- `nexo_control_federation_errors_total{peer,code}`。

日志必须包含 `request_id`、`peer_id`、`node_id`、`status` 和耗时；不得记录 Authorization 头和响应正文。

## 14. Web UI 设计

增加 `Fleet` 页面，但不改变现有单机页面的含义：

- Gateway、Routes、Certificates、Traffic 默认仍展示本机；
- Fleet 展示节点卡片、联邦总览和链路图；
- 进入某个远端节点时，使用协调器缓存，而不是浏览器直连 peer；
- 卡片显示 `fresh/stale/offline/identity_mismatch`；
- 所有联邦数值显示数据时间和聚合警告；
- 无协调器配置时，Fleet 页面显示“未启用协调器”，不伪造空的在线节点。

浏览器只与本机 Web UI 通信。Web UI 后端调用本机控制面服务，避免把 peer 令牌暴露给前端。

## 15. 与现有代码的映射

建议新增包和职责：

~~~text
internal/control/
  server.go          # 控制面 HTTP listener、中间件、认证
  resources.go       # Node/Route/Certificate/Traffic/Link 资源构造
  snapshot.go        # 一致快照与 ETag
  federation.go      # coordinator peer 拉取、缓存、状态机
  aggregate.go       # 联邦聚合与 warning
  topology.go        # 显式/推导链路与环路检测
~~~

现有模块的边界：

- `pkg/config` 解析 `control_plane`，但不负责网络请求。
- `pkg/traffic.Manager` 提供只读快照，不知道 peer 和联邦聚合。
- `pkg/cert.Manager` 提供脱敏证书状态，不暴露密钥材料。
- `internal/server.Server` 启动和停止控制面 listener；数据面逻辑不依赖协调器。
- `internal/webui` 读取 `internal/control` 的本地联邦视图，不能直接访问远端。

控制面 API 不应复用现有 Web UI 的 Cookie、CSRF 或 HTML handler。Web UI 的用户认证与节点间认证是两条独立信任链。

## 16. 迁移与兼容

### 16.1 单机用户

无需改配置。`control_plane.enabled` 默认 `false`，现有行为不变。

### 16.2 开启被观察节点

1. 生成唯一 `node.id` 和控制令牌。
2. 配置独立 `listen` 地址。
3. 加入网络 ACL，只允许协调器访问。
4. 启动后用 `/healthz`、`/node`、`/capabilities` 验证。

### 16.3 开启协调器

1. 在主节点开启 `coordinator.enabled`。
2. 为每个 peer 创建独立令牌并配置 URL。
3. 验证 `identity_mismatch`、超时和离线恢复。
4. 打开 Fleet 页面，确认链路和聚合告警。

### 16.4 旧数据

- 现有 `traffic.json` 继续作为本机数据源。
- 首次读取路由时为旧域名生成稳定 `route_id`；迁移后保持不变。
- 远端快照不写入本机 `traffic.json`，升级和回滚不会污染本机历史。

## 17. 分阶段实现计划

### Phase 1：本地只读控制面

- 配置、节点身份、Bearer 认证；
- `/healthz`、`/node`、`/capabilities`、`/snapshot`；
- Node、Route、Certificate、TrafficSummary 资源；
- 单元测试、响应大小限制、敏感字段脱敏。

### Phase 2：协调器与联邦缓存

- peer 拉取、超时、退避和状态机；
- `/fleet/snapshot`、聚合 warning、ETag；
- 端到端测试：正常、超时、恢复、身份不匹配。

### Phase 3：显式拓扑与 Fleet UI

- `route_id`、`backend_ref`、`Link` 资源；
- 环路检测、未知目标和链路状态；
- Fleet 页面和节点筛选。

### Phase 4：增强能力

- HTTPS/mTLS；
- SSE watch；
- Metric、Probe、Alert 扩展资源；
- 经过审计的异步命令 API。

## 18. 测试要求

- API 合约测试：字段、错误码、未知字段兼容和 HTTP 状态。
- 安全测试：未认证、错误令牌、重放、超大请求、敏感字段泄露。
- 联邦测试：并发拉取、部分失败、缓存过期、身份漂移和恢复。
- 拓扑测试：显式链路优先、推导链路、未知目标和环路。
- 性能测试：控制面高并发读取不影响代理请求延迟。
- 兼容测试：旧节点与新协调器、新节点与旧协调器的 capability 降级。

## 19. 方案取舍

### 为什么采用协调器主动拉取

主动拉取配置简单，适配 NAT，节点无需保存其他节点地址，也不会因一个节点故障阻塞全局。代价是存在轮询延迟；v1 用 `poll_interval` 和 ETag 控制成本，实时场景留给未来 watch。

### 为什么不直接复用 Web UI API

Web UI API 是面向浏览器的页面协议，依赖 Cookie、CSRF 和本机会话；它没有节点身份、资源版本和联邦语义。复用会把用户会话误当成机器信任链，且难以演进。

### 为什么第一版只读

远程写路由、证书和密钥的失败代价高，且需要权限、审计、回滚和幂等语义。先稳定资源模型和观测链路，再增加命令 API，能避免把控制面做成不可逆的远程 shell。

## 20. 未决事项

以下事项不阻塞 v1，但应在实现前确认：

1. 生产环境是否统一由现有网关终止 HTTPS，还是由 Nexo 控制面原生提供 TLS。
2. 跨节点流量是否允许发送可逆 IP；默认实现按 hash/redact 处理。
3. 是否需要一个独立的 CLI，以及 CLI 是否复用 Web UI 用户认证。
4. 是否把 `Probe` 作为内置资源，还是先由外部监控系统消费 Route 状态。

## 21. 验收标准

实现达到以下条件才算完成 Phase 1–3：

- 两台 Nexo 可通过独立令牌完成节点发现；
- 任意一台停止后，协调器在 `stale_after` 内显示 stale，连续失败后显示 offline；
- 联邦快照能区分本机、远端、快照时间和聚合告警；
- 链路图能展示至少一条 `node A -> route A -> node B -> route B`，并正确标出未知目标和环路；
- 未配置控制面时，现有单机启动和 Web UI 测试全部通过；
- 控制面响应中不存在密码、Token、私钥和原始配置文件内容；
- 增加未知字段不会使现有客户端失败，缺少可选能力时能按 `capabilities` 降级。
