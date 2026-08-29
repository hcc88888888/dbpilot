# DBPilot 全栈 Docker Compose 验收环境设计

> 状态：聊天设计已确认，待书面复核

## 1. 目标

建立一套可在 Windows Docker Desktop 上重复执行、成功或失败均自动清理的 DBPilot 全栈验收环境，使用生产 control plane 与 Agent 二进制验证：

- 浏览器到 control plane 的真实 OIDC Bearer、issuer、audience、JWKS 和 RBAC。
- Agent 到 control plane 的 gRPC mTLS、SPIFFE 身份、Hello/HelloAck、Heartbeat 和 capability 协商。
- TelemetryIngest 指标传输、服务端 `accepted_at` 和 PostgreSQL 持久化。
- AgentControl `Prepare → Start → Progress/Result → ResultAck` 两阶段命令生命周期。
- 主机巡检、Finding、partial Run、HTML/JSON Report、Artifact 和 Audit 闭环。
- control plane 重启后的 Agent 自动重连与本地 spool 补发。
- 非法证书和 Agent ID/SPIFFE 不一致的拒绝路径。
- 容器、网络、卷、临时证书、密钥、配置和构建产物的精确清理。

验收环境不是 mock control plane 或 mock Agent。测试 fixture 仅用于 OIDC 身份提供方、证书/配置生成和断言驱动。

## 2. 第一阶段范围

### 2.1 包含

- `postgres:16-alpine` 数据库，不发布宿主机端口。
- `golang:1.27.0-bookworm` 一次性静态构建和 bootstrap 工具构建。
- 精确镜像 `cr.kylinos.cn/kylin/kylin-server-platform:v10sp1` 中运行的 control plane 与 Agent。
- 仓库内自研 HTTPS OIDC fixture，提供 discovery、JWKS 和短期测试 token。
- Nginx 静态前端与 `/api` HTTPS 反向代理。
- `mcr.microsoft.com/playwright:v1.62.0-noble` 浏览器验收 runner；Playwright 包版本必须与镜像一致。
- 一个真实在线 Agent 与一个仅存在于 control plane inventory 的离线 Agent。
- 正常链路、control plane 重启、spool 补发、非法证书拒绝四类通信场景。
- API、浏览器、PostgreSQL、Agent journal 四个事实面的交叉断言。

### 2.2 不包含

- 正式 OIDC Authorization Code + PKCE 登录页面、刷新 token、退出和会话恢复。
- React/Vue/TypeScript/Vite 迁移。
- PostgreSQL 服务端 TLS；PostgreSQL 只存在于隔离的内部 Compose 网络。
- 多 control plane/Agent 高可用、负载和容量测试。
- SQL 数据库探针和真实数据库变更命令。
- CentOS/Kylin VM 或裸机 systemd、journald、内核、网络和 SELinux 发布证据。

上述项目不阻塞 Compose 功能验收，但生产发布前必须按各自风险单独验证。

## 3. 服务拓扑

```text
asset-builder (one-shot, Go 1.27)
  -> /acceptance/bin

bootstrap (one-shot, repository fixture binary)
  -> /acceptance/secrets
  -> /acceptance/config
  -> /acceptance/state

postgres

oidc (HTTPS fixture)
  -> discovery / JWKS / token

controlplane (Kylin V10, production binary)
  -> PostgreSQL
  -> OIDC HTTPS fixture
  -> Artifact volume
  -> HTTP TLS :8443
  -> gRPC mTLS :9443

agent (Kylin V10, production binary)
  -> gRPC mTLS controlplane:9443
  -> signed telemetry policy
  -> bbolt journal + spool volume

frontend (Nginx)
  -> static repository frontend
  -> /api proxy to controlplane HTTPS
  -> only host-published port: 127.0.0.1::<ephemeral>

acceptance-runner (Playwright)
  -> OIDC short-lived token
  -> browser frontend flow
  -> API negative/positive assertions
```

所有服务位于一个专用 Compose 网络。除前端临时 loopback 端口外，不发布 PostgreSQL、OIDC、HTTP 或 gRPC 端口到宿主机。

## 4. 构建与运行镜像

### 4.1 asset-builder

`asset-builder` 使用 `golang:1.27.0-bookworm`，通过非登录 `/bin/sh -ec` 执行，避免登录 shell 覆盖镜像 Go PATH。它构建：

- `dbpilot-controlplane` linux/amd64，`CGO_ENABLED=0`。
- `dbpilot-agent` linux/amd64，`CGO_ENABLED=0`。
- `dbpilot-fullstack-fixture` linux/amd64，包含 `bootstrap`、`oidc` 和断言辅助子命令。

产物写入 Compose 命名卷，运行容器只读挂载。构建服务不缓存用户主机凭据，不写入仓库工作树。

### 4.2 Kylin runtime

control plane、在线 Agent、rogue Agent 均从精确 Kylin V10 SP1 镜像启动，通过只读命名卷挂载静态二进制。启动时必须校验 `/etc/os-release`、`x86_64` 和二进制 `--version`。

### 4.3 Frontend

第一阶段使用 Nginx 提供当前原生 HTML/CSS/ES Modules。Nginx 仅在内部网络代理 `/api/` 至 control plane HTTPS，并使用 bootstrap CA 校验上游证书。

外部 loopback 入口可以使用 HTTP，因为它只服务验收机本地临时端口；容器间 control plane/OIDC/Agent 通信保持 TLS/mTLS。生产部署仍必须使用外部 HTTPS。

## 5. Bootstrap 和秘密材料

仓库内 fixture 使用 Go 标准库生成，不依赖宿主机 OpenSSL：

- 一次性 Ed25519 测试 CA。
- control plane HTTP 服务器证书，DNS SAN 包含 `controlplane`。
- control plane gRPC 服务器证书，DNS SAN 包含 `controlplane`。
- 合法 Agent 客户端证书，URI SAN 为 `spiffe://dbpilot.local/agent/agent-online`。
- SPIFFE/Agent ID 不匹配证书。
- 未受信任 CA 签发的 rogue Agent 证书。
- OIDC HTTPS 服务器证书，DNS SAN 包含 `oidc`。
- OIDC RS256 签名私钥和公开 JWKS。
- control plane Ed25519 command 签名密钥及 Agent PKIX 公钥。
- 32 字节 execution-token AES 密钥。
- Artifact HMAC 签名密钥。
- Agent 签名遥测策略及策略公钥。
- control plane、Agent、OIDC、Nginx 和 runner 所需配置。

秘密写入临时命名卷中的固定目录，私钥为 0600，目录为 0700。日志、Compose config 输出、测试失败消息和浏览器 DOM 不得包含私钥、完整 JWT、数据库密码或连接串。

所有 token 的有效期不超过 15 分钟，issuer 固定为 `https://oidc:9444`，audience 固定为 `dbpilot-control-plane`。

## 6. OIDC 和前端认证

### 6.1 OIDC fixture

fixture 提供：

- `GET /.well-known/openid-configuration`
- `GET /jwks`
- `POST /token`
- `GET /healthz`

`/token` 只接受 Compose 内部网络请求和一个 bootstrap 生成的随机验收凭据，返回短期 RS256 JWT。JWT 包含：

- `sub: acceptance-admin`
- 正确 `iss`、`aud`、`iat`、`exp`
- tenant/project：`tenant-acceptance/project-acceptance`
- inspection view/manage/execute、Job cancel、Artifact read/download、Audit read 权限

runner 还生成 wrong-audience、expired 和缺少权限 token，用于 401/403 断言。

### 6.2 Frontend token provider

新增可选 bootstrap：

```javascript
window.DBPILOT_GET_ACCESS_TOKEN = async () => shortLivedToken;
```

`frontend/app.js` 把该函数传给真实 inspection/report API adapter。未配置 control plane 时仍使用现有显式 demo；已配置 control plane 但 token 缺失或 401/403/5xx 时绝不回退 demo。

Playwright 通过 `page.addInitScript` 注入短期 token provider、control plane same-origin URL、scope 和权限。静态前端文件不保存 token，Nginx 不提供 token 接口。

此 bootstrap 是正式 PKCE 客户端落地前的窄认证边界，后续 OIDC 客户端只需实现同一 `getAccessToken` 接口。

## 7. Control plane 与 Agent 通信验收

### 7.1 正常连接

在线 Agent 必须：

1. 使用受信任 mTLS 证书连接 `controlplane:9443`。
2. Hello 中 Agent ID 与证书 SPIFFE ID 一致。
3. 收到 HelloAck。
4. 广告 `collect_now`、`collect_now.host.v1` 和实际安装的其他 capability。
5. 持续发送 Heartbeat。

control plane 必须将 Agent 映射到固定 tenant/project inventory，Agent payload 不得覆盖 scope。

### 7.2 TelemetryIngest

签名策略启用 host metrics 与一个受控文件日志源。fixture 在 Agent 容器内写入一条非敏感 warning/error 测试日志，使日志摘要窗口可用。

验收断言：

- Agent 在断网前后都能把 metric/log batch 写入 spool。
- control plane 恢复后接收批次并写入 `metric_samples.accepted_at`。
- source 必须为 `inspection-host-snapshot` 或签名策略声明的 source。
- 断线期间生成的 batch 不丢失，不重复形成逻辑样本。

### 7.3 AgentControl

浏览器创建一次包含 `agent-online` 和 `agent-offline` 的立即巡检：

- online command 经历 Prepare、Start、Result 和 ResultAck。
- Agent journal 中同一 command 最终为已报告，没有 pending Result。
- offline target 使用稳定 `agent_offline`。
- online target 产生完整 13 项 Finding，无 `missing_data`/`unsupported`。
- Run 最终为 `partial`。

### 7.4 重启恢复

宿主 PowerShell 验收器在第一阶段成功后执行：

1. 停止 control plane 容器。
2. 等待 Agent 至少产生一个周期遥测批次并进入 spool。
3. 重新启动 control plane。
4. 等待 Agent 自动重连、Hello/Heartbeat 恢复。
5. 验证断线批次被接收并清除，原 journal/ResultAck 状态保持一致。

ResultAck 丢失重放的精确 command 级竞态继续由 foundation PostgreSQL E2E 覆盖；Compose 只验证真实进程重启与 spool 恢复，不引入代理层 mock。

### 7.5 非法证书

分别运行两个一次性 rogue Agent：

- 未受信任 CA 证书：TLS 握手必须失败。
- 受信任证书但 SPIFFE ID 与 Hello Agent ID 不一致：AgentControl 必须返回 PermissionDenied。

两者不得在 registry、metric_samples、Job、Command 或 Audit 中创建合法 Agent 记录。

## 8. 浏览器验收流程

runner 使用与镜像匹配的 Playwright 1.62.0：

- runner 使用独立、提交到仓库的 `package.json` 与 lockfile，固定 `@playwright/test` 1.62.0。
- Microsoft 镜像只提供浏览器和系统依赖；runner 构建阶段执行 `npm ci` 安装匹配版本的测试包。

1. 打开 Nginx 前端 `#inspection`。
2. 确认来源为控制面而非演示数据。
3. 确认两个目标和 13 个系统巡检项可见，支持跨页数据。
4. 创建 label 或显式目标策略并校验 ETag 编辑。
5. 发起包含 online/offline 的立即巡检。
6. 轮询 UI，直到 Run 为 `partial`。
7. 查看 online target 的 13 项 Finding、证据、阈值和建议。
8. 查看 Job、Command、Audit 引用。
9. 分别点击 HTML、JSON 下载并校验内容类型、校验和和 Run ID。
10. 使用无权限 token 重新打开页面，确认固定 403 状态且不回退演示。

runner 保存失败时的 screenshot、DOM 摘要和脱敏日志到临时 artifact 目录；成功默认不保留浏览器 trace。

## 9. 数据库验收

runner 或 fixture 通过内部 PostgreSQL 只读验收账号验证：

- 一个 Run、两个 TargetRun、两个 Command。
- online target 13 个不可变 Finding，offline target 无伪造 Finding。
- 一个不可变 Report，两个 Artifact 元数据和可读取 blob。
- Audit 包含真实 Run、Job、Command、request、trace 关联。
- Run/Audit/idempotency 重放不会产生重复行。
- metric samples 包含正确 Agent、source、sampled_at 和 accepted_at。
- Agent journal 中 terminal Result 已被 ResultAck。

验收查询必须使用明确列和固定 scope，不输出秘密字段。

## 10. Compose 生命周期与清理

第一阶段提供一个入口：

- `backend/scripts/verify-full-stack-compose.ps1`：全自动执行并始终清理。

人工保活、登录和交互查看依赖正式 OIDC/PKCE 或单独的安全验收会话设计，不在第一阶段提供。失败排查使用脱敏 screenshot、DOM 摘要和容器日志，避免把短期 token 写入静态文件或打印到终端。

验证器使用唯一 Compose project name 和 ownership labels，记录：

- 每个容器 ID。
- 网络 ID。
- 命名卷和匿名卷 ID。
- 临时目录绝对路径。
- 前端实际临时端口。

`finally` 只删除已记录且 ownership label 匹配的资源。清理完成后再次查询并要求零残留。不得使用宽泛 `docker system prune`、名称通配删除或删除其他 DBPilot 项目资源。

## 11. 健康检查和等待

依赖顺序：

```text
asset-builder completed
  -> bootstrap completed
    -> postgres healthy + oidc healthy
      -> controlplane ready
        -> agent Hello/Heartbeat observed
          -> frontend healthy
            -> acceptance-runner
```

不得使用固定长 sleep 代替状态等待。每个等待有明确超时、失败日志和最终状态：

- PostgreSQL：`pg_isready`。
- OIDC：HTTPS `/healthz`。
- control plane：HTTPS `/readyz`。
- Agent：control plane registry/target API 显示 online + host.v1。
- Frontend：Nginx health endpoint。
- Run：API/页面状态轮询。

## 12. 文件结构

建议新增：

```text
backend/test/fixtures/fullstack/
  main.go
  bootstrap.go
  oidc.go
  assertions.go

backend/test/e2e/full_stack_compose_test.mjs
backend/test/e2e/full-stack/package.json
backend/test/e2e/full-stack/package-lock.json

backend/docker/full-stack/
  docker-compose.yml
  nginx.conf
  controlplane.yaml
  agent.yaml
  README.md

backend/scripts/verify-full-stack-compose.ps1
tests/contracts/full-stack-container-safety.test.mjs
```

可复用现有 `container-safety.ps1`、证书生成模式、Kylin verifier、host inspection E2E 和生成客户端，不复制其安全逻辑。

## 13. 验收门禁

完成条件：

- Compose 配置验证通过且镜像均使用精确 tag；发布流程可进一步锁定 digest。
- 生产 control plane/Agent 在 Kylin V10 SP1 amd64 中运行。
- OIDC 正向 token 成功，wrong audience/expired/permission token 失败。
- mTLS 正向、未信任证书和 SPIFFE/Hello mismatch 均有证据。
- TelemetryIngest、AgentControl、Heartbeat、Prepare/Start/Result/ResultAck 全部通过。
- control plane 重启后 Agent 重连、spool 补发通过。
- 浏览器巡检/报告/双格式下载通过。
- PostgreSQL/journal 交叉断言通过。
- 成功和故意失败路径的清理审计均为零残留。
- 现有 contracts、Node、Go、vet、PostgreSQL、foundation、Kylin 门禁无回归。

## 14. 后续事项

以下能力后续独立实施，不阻塞本验收环境：

- 正式前端 OIDC Authorization Code + PKCE。
- React/Vue + TypeScript + Vite 渐进迁移。
- PostgreSQL TLS 和外部秘密管理系统。
- 多实例 HA、压力、容量和长稳测试。
- Kylin VM/裸机 systemd、journald、内核、网络和 SELinux。
- SQL 数据库探针和其他功能模块全栈场景。
- Compose 镜像 digest 自动更新与供应链签名。
