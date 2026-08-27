# DBPilot 前后端与 Agent 接口契约及并行开发设计

日期：2026-08-28
状态：已确认

## 1. 背景与目标

DBPilot 将继续采用前端自研、后端按模块复用成熟设计或代码的混合模式。为了让前端、控制面后端、Agent 及不同业务模块并行开发，需要先建立唯一、稳定、可生成代码且可自动验证的接口契约。

本设计目标：

- 浏览器与控制面使用 OpenAPI 3.1 REST 契约。
- 控制面与 Agent 使用 Protobuf/gRPC 契约。
- 契约是接口的唯一事实来源，前后端不得维护重复模型。
- 自动生成前端客户端、Go 类型与服务接口，并将生成物提交仓库。
- 使用统一 Job/Command 模型承载耗时操作、批量执行和 Agent 命令。
- 统一身份、权限、审计、错误、分页、幂等、并发控制和可观测性。
- 各模块可在共享基础契约稳定后独立实现和验证。

本阶段不改变已经确认的产品范围，不恢复 Redis 慢查询、敏感数据扫描或敏感数据脱敏功能，也不要求一次性重写全部现有页面。

## 2. 总体架构

```text
Browser
  │ OpenAPI 3.1 / HTTPS / OIDC Bearer
  ▼
DBPilot Control Plane
  ├─ Module Handler → Module Service → Repository
  ├─ Job Service → Transactional Outbox → Command Dispatcher
  ├─ Artifact / Audit / Capability / Credential Reference
  └─ Telemetry Ingest
          ▲
          │ Protobuf/gRPC bidirectional stream / mTLS + SPIFFE
          │ metrics, logs, inventory, commands, progress, results
          ▼
DBPilot Agent
  ├─ Metric collectors
  ├─ Database / OS / custom log collectors
  ├─ Custom metric collectors
  ├─ Typed command executors
  └─ Durable local journal
```

浏览器不直接连接 Agent。模块服务不能绕过 Job Service 直接下发远程操作。Agent 不暴露任意 Shell 执行接口。

## 3. 契约与生成代码目录

```text
contracts/
  openapi/
    dbpilot-api.yaml
    common/
      identifiers.yaml
      pagination.yaml
      errors.yaml
      jobs.yaml
      permissions.yaml
      audit.yaml
    modules/
      dashboard.yaml
      instances.yaml
      monitoring.yaml
      alerts.yaml
      sql-review.yaml
      workorders.yaml
      inspections.yaml
      reports.yaml
      modules.yaml
  protobuf/dbpilot/agent/v1/
    telemetry.proto
    policy.proto
    command.proto
    inventory.proto
  examples/
    <module-name>/
frontend/generated/api/
backend/gen/openapi/
backend/gen/agent/v1/
```

`modules.yaml` 负责聚合其余业务模块，每个成熟模块应拆分为独立契约文件，避免多人频繁修改根文件。`dbpilot-api.yaml` 只负责组合公共定义和模块路径。

现有 `backend/api/telemetry/v1/telemetry.proto` 在 Agent v1 稳定前一次性迁移到上述规范目录。现有手写 `/api/v1` 路由属于稳定前接口，允许进行一次兼容迁移；生成客户端和严格服务接口完成对齐后，v1 进入稳定期。

### 3.1 所有权与隔离规则

- `contracts/openapi/common` 和 Agent 公共 Protobuf 由平台基础组维护。
- 每个业务模块拥有自己的 OpenAPI 文件、示例、Handler、Service 和测试。
- 模块不得直接修改其他模块的请求或响应结构。
- 公共模型只有被至少两个模块稳定复用时才可进入 `common`。
- OpenAPI 与 Protobuf 是唯一事实来源；手写 DTO 不得复制契约模型。
- 生成代码必须提交，以支持前端和后端在缺少本地生成工具时继续开发。
- CI 重新生成代码并检查 `git diff`，防止契约与生成物漂移。

## 4. Browser 到 Control Plane REST 规范

### 4.1 路径、命名和类型

- 基础路径：`/api/v1/tenants/{tenant_id}/projects/{project_id}`。
- 资源路径使用 kebab-case 复数名词，如 `/alert-rules`。
- JSON 字段统一 snake_case。
- ID 是不可推断的字符串，不向调用方暴露数据库自增键语义。
- 时间统一使用 UTC RFC 3339。
- 有单位的数值必须在字段名中标明单位，如 `timeout_seconds`、`duration_ms`、`size_bytes`。
- 单实体直接返回实体；列表统一返回 `{items, page}`。
- 分页采用 cursor：`page.limit`、`page.next_cursor`、`page.has_more`。
- 不增加通用 `data` 包装层。

### 4.2 HTTP 操作语义

- `GET /resources`：查询列表。
- `POST /resources`：创建资源。
- `GET /resources/{id}`：查询详情。
- `PATCH /resources/{id}`：部分更新。
- `DELETE /resources/{id}`：删除资源。
- `POST /resources/{id}/actions/{action}`：显式业务动作。
- 同步创建成功返回 `201 Created`，同步动作成功返回 `200 OK` 或 `204 No Content`。
- 耗时、批量或有远程副作用的动作返回 `202 Accepted`，响应体为 Job，并设置 `Location` 到 Job 资源。
- 所有写操作支持 `Idempotency-Key`。
- 配置资源使用 `ETag` 和 `If-Match` 防止并发覆盖；版本不匹配返回 `412 Precondition Failed`。

### 4.3 错误模型

错误响应使用 `application/problem+json`，遵循 RFC 9457，并扩展以下字段：

| 字段 | 说明 |
| --- | --- |
| `type` | 稳定的错误说明 URI |
| `title` | 可安全展示的中文摘要 |
| `status` | HTTP 状态码 |
| `detail` | 不包含敏感数据的上下文 |
| `instance` | 当前请求路径或问题实例 URI |
| `code` | 稳定、可编程处理的错误码 |
| `request_id` | 全链路请求标识 |
| `errors` | 可选字段校验错误数组 |

业务代码不得依赖 `title` 或 `detail` 文案判断错误，只能使用 HTTP 状态码和 `code`。

### 4.4 身份与权限

- 浏览器通过企业 OIDC 获取短期 Bearer Token。
- 控制面从可信身份声明解析用户身份，不接受客户端伪造 actor 字段。
- 权限判定维度为 tenant、project、instance 和 action。
- OpenAPI Operation 使用 `x-dbpilot-permission` 标注所需权限。
- 列表接口必须在服务端按授权范围过滤，不能只依赖前端隐藏菜单。
- `/capabilities` 返回当前部署、数据库类型及用户权限共同允许的能力，用于控制 UI 入口。
- 数据库密码、Token 和私钥仅以 Credential Reference 传递，接口不返回明文凭据。

## 5. 统一 Job 模型

### 5.1 适用范围

巡检、报告生成、SQL 执行、工单执行、结构对比、诊断、参数调优、索引分析、批量执行、备份恢复和需要 Agent 操作的任务均使用 Job。

### 5.2 状态机

```text
queued → dispatched → running → succeeded
                         ├──────→ failed
                         ├──────→ timed_out
                         └→ cancelling → cancelled
```

Job 至少包含：

- `id`、`type`、`status`、`outcome`。
- tenant、project、instance 或批量目标引用。
- 发起人、来源业务资源、幂等键。
- 创建、派发、开始、结束和超时时间。
- 总进度、已完成/失败/跳过目标数。
- 错误摘要、结果摘要和 Artifact 引用。
- `request_id`、`trace_id`。

多目标任务允许部分成功，此时终态可以是 `succeeded`，同时 `outcome=partial` 并给出各目标结果；调度器或平台故障导致无法完成时使用 `failed`。

### 5.3 一致性与恢复

- 业务资源和 Job 在同一数据库事务内创建。
- 使用 transactional outbox 发布待派发命令，避免“业务已提交但命令丢失”。
- 一个 Job 可聚合多个 Command，服务端根据 Command 进度计算 Job 进度。
- Job 支持查询、取消、超时和有策略的重试。
- 重试复用业务幂等语义，但每次实际执行拥有独立 Command ID。

## 6. Artifact 规范

大型结果、日志片段、报告、导出文件、执行计划和诊断包存入对象存储或文件存储。业务实体与 Job 只保存 Artifact 元数据和引用：

- `artifact_id`、`kind`、`content_type`、`size_bytes`、`checksum`。
- tenant/project/业务资源归属。
- 创建者、创建时间、过期时间。
- 受控下载地址或下载动作。

API 响应不得内嵌无限增长的日志和大文件正文。

## 7. Control Plane 到 Agent gRPC 规范

### 7.1 连接模型

Agent 主动建立长连接：

```protobuf
service AgentControl {
  rpc Connect(stream AgentMessage) returns (stream ServerMessage);
}
```

独立的 `TelemetryIngest` 服务承载指标、日志和事件批次，避免命令控制流被大批量遥测阻塞。连接建立后先执行 Hello 与能力协商，再进入心跳、策略同步、命令和状态上报阶段。

### 7.2 消息范围

Agent 上行消息包含：

- Hello、Agent 版本、OS/架构、数据库适配器与能力清单。
- Heartbeat、资源状态、策略版本和本地队列状态。
- Inventory 快照或增量。
- Command 接收确认、进度、结果和错误。
- 指标、数据库日志、操作系统日志、自定义日志及自定义指标批次。

Server 下行消息包含：

- 配置和采集策略更新。
- Command 派发与取消。
- Inventory/采集即时请求。
- 流控、租约续期和服务端能力信息。

### 7.3 类型化命令

`Command` 使用 Protobuf `oneof`，首批类型为：

- `CollectNow`
- `InspectInstance`
- `ExecuteSQL`
- `ExecuteRegisteredProcess`
- `CollectDiagnostic`

不提供任意 Shell 字符串执行。操作系统工具必须注册为受控 process ID，并使用结构化、可校验参数。`ExecuteSQL` 必须携带：

- `instance_id`
- `workorder_id`
- `review_revision`
- `sql_digest`
- `transaction_policy`
- `timeout_seconds`

Agent 在执行前验证命令类型、能力、目标、有效期和签名；高风险数据库动作仍需由控制面完成权限和审批校验。

### 7.4 可靠性与安全

- 传输采用 mTLS，并使用 SPIFFE 身份标识 Agent 与服务端。
- Command Envelope 包含 `command_id`、签名、签发时间、过期时间和 nonce。
- 交付语义为 at-least-once；Agent 按 `command_id` 去重。
- Agent 使用 bbolt 持久化命令日志、执行状态和必要的待上传元数据。
- 断线重连后，Agent 先报告未完成和最近完成的命令，服务端再决定续租、取消或重试。
- Command 使用 lease 与 heartbeat 判定失联，超过最终期限进入 `timed_out`。
- 大输出上传为 Artifact，Command Result 只包含摘要和引用。

## 8. 公共控制面服务

| 服务 | 职责 |
| --- | --- |
| Instance Registry | 实例、数据库类型、连接引用、Agent 绑定和拓扑 |
| Job Service | 异步状态机、进度、取消、重试、超时和结果聚合 |
| Artifact Service | 大型结果的存储、授权、校验和生命周期 |
| Audit Service | 统一记录用户、系统、Agent 和 AI 动作 |
| Capability Service | 计算部署、适配器、数据库和权限能力 |
| Credential Reference | 以引用方式管理凭据，隔离业务模块与密钥实现 |

标准调用链：

```text
Browser → generated REST client → Module Handler → Module Service
  → synchronous repository
  或 → Job Service → Outbox → Command Dispatcher → Agent
       → progress/result → Job + Artifact + Audit
```

## 9. 业务模块接口边界

| 模块 | 主要资源或入口 |
| --- | --- |
| Dashboard | `/dashboard/overview` |
| 实例管理 | `/instances`、`/instance-groups`、`/topology` |
| 基础监控 | `/monitoring/overview`、`/metric-series`、`/metric-catalog` |
| 告警管理 | `/alert-events`、`/alert-rules`、`/notification-policies`、`/silences` |
| SQL 审核 | `/sql-reviews`、`/sql-review-rules`、`/sql-review-integrations` |
| SQL 改写 | `/sql-rewrites`、`/sql-rewrite-validations` |
| 工单管理 | `/workorders` 及其审批、执行、取消和回滚动作 |
| SQL 窗口 | `/sql-sessions`、`/sql-queries`、`/query-history` |
| 版本列表 | `/sql-versions`、`/sql-version-items` |
| 实例巡检 | `/inspection-policies`、`/inspection-runs`、`/inspection-items` |
| 性能洞察 | `/performance-incidents`、`/performance-analyses` |
| 根因诊断 | `/diagnoses`、`/diagnosis-evidence` |
| 慢 SQL 治理 | `/slow-sql-fingerprints`、`/slow-sql-samples`、`/slow-sql-analyses` |
| 锁透视 | `/lock-events`、`/lock-snapshots`、`/transaction-replays` |
| 会话与限流 | `/database-sessions`、`/sql-rate-limits` |
| 索引推荐 | `/index-recommendations`、`/index-analysis-runs` |
| 结构对比 | `/schema-diffs`、`/schema-diff-items` |
| 存储分析 | `/storage-snapshots`、`/storage-forecasts` |
| 参数管理 | `/parameter-snapshots`、`/parameter-changes` |
| 参数调优 | `/parameter-recommendations`、`/tuning-runs` |
| 自治管理 | `/autonomy-policies`、`/autonomy-actions` |
| 审计日志 | `/audit-events`、`/audit-statistics`、`/audit-exports` |
| 报告中心 | `/report-templates`、`/reports`、`/report-schedules` |
| 账号权限 | `/database-accounts`、`/database-grants` |
| AI 小助手 | `/ai/conversations`、`/ai/messages`、`/ai-agent-runs` |
| 批量执行 | `/execution-batches`、`/execution-targets` |
| 备份恢复 | `/backup-policies`、`/backup-runs`、`/restore-plans` |

跨模块约束：

- SQL 审核只产出审核结果，不直接执行 SQL；审核版本 `review_revision` 不可变。
- 工单绑定 `review_revision` 与 `sql_digest`，避免审批后 SQL 被替换。
- 索引、结构和参数建议的实施必须转为工单。
- AI 只能调用同一权限与审批链路，不能绕过 RBAC、SQL 审核或人工审批。
- Dashboard 只读取聚合查询模型，不跨模块拼接大量明细。
- 所有模块统一调用 Audit Service。

## 10. 审计与可观测性

所有请求传播：

- `request_id`
- W3C `traceparent` / `trace_id`
- `job_id`
- `command_id`
- tenant、project、actor

审计事件统一记录：actor、action、resource、tenant/project、来源 IP、客户端、请求与结果摘要、前后状态摘要、关联 Job/Command、时间、结果和稳定错误码。SQL 正文、凭据和敏感结果按数据分级策略处理，默认只记录摘要或 digest。

## 11. 生成工具与运行方式

- OpenAPI 校验与 bundle：Redocly CLI。
- Go 严格服务接口与类型：oapi-codegen。
- 前端客户端：OpenAPI Generator `typescript-fetch`。
- TypeScript 仅用于生成流水线；编译结果输出浏览器原生 ES Module 与 `.d.ts`，现有生产前端继续使用原生 JavaScript。
- REST Mock：Prism，优先通过 Docker 运行。
- Protobuf 管理：Buf。
- Go gRPC：`protoc-gen-go`、`protoc-gen-go-grpc`。
- Go Schema/Handler 测试：kin-openapi、`httptest`。

所有工具版本锁定在仓库配置中，生成命令通过统一脚本或 Make/PowerShell 入口执行，避免开发者本地版本差异。

## 12. Mock、测试与 CI 门禁

每个模块契约包必须同时提供 OpenAPI、请求响应示例、生成的前端客户端、生成的 Go 接口和契约测试。

CI 顺序：

1. OpenAPI lint 与 bundle。
2. Buf lint 和 breaking change 检查。
3. 重新生成前端、Go 和 Protobuf 代码，检查工作区无 diff。
4. 前端针对 Prism Mock 运行契约测试。
5. Go Handler 响应通过 OpenAPI Schema 校验。
6. 验证 Job 与 Command 状态、错误和取消语义映射。
7. 运行模块单元测试、集成测试和关键回归测试。

前端可在后端实现前连接 Prism 开发。模块已有 demo adapter 可临时保留，但接入生成客户端后必须删除该模块的私有重复 DTO 和静态业务数据；演示数据统一来自契约 examples 或 Mock 场景。

## 13. 兼容性规则

- v1 稳定后只允许增加可选字段、资源或操作。
- 删除字段、改变含义、收紧必填、改变枚举语义或路径属于破坏性变更。
- 客户端必须容忍未知响应字段与未知枚举值，并提供 `unknown` 降级展示。
- 破坏性 REST 变更发布 `/api/v2`；破坏性 Agent 协议变更发布新的 Protobuf package。
- Agent Hello 协商版本和能力；控制面不得向不支持某能力的 Agent 派发命令。
- 数据库适配差异通过 capability 表达，不能靠前端硬编码数据库类型分支猜测。

## 14. 模块完成定义

一个模块只有同时满足以下条件才视为“已实现”：

- OpenAPI 契约与示例通过校验。
- 生成代码已更新且 CI 无漂移。
- 前端使用生成客户端，不再依赖模块私有 demo 数据。
- Go Handler 实现生成的严格接口。
- 认证、权限和范围过滤测试通过。
- 错误符合 Problem Details 规范。
- 耗时或远程操作接入 Job、Artifact、Audit。
- 涉及 Agent 时具备 Command 映射、去重、超时和结果测试。
- `/capabilities` 正确反映模块和数据库适配能力。
- 包含运行、回滚和兼容说明。

不影响功能交付的安全加固或工程优化可以登记为后续项，但认证绕过、越权、命令注入、数据破坏、错误执行或导致核心功能不正确的问题必须立即阻断和修复。

## 15. 实施阶段

### 阶段一：公共契约基础

- 建立 common OpenAPI、根 bundle、代码生成入口和 Prism。
- 实现 Job、Artifact、Audit、Capability 公共接口。
- 建立 AgentControl、TelemetryIngest、Command 与 Capability Protobuf。
- 完成现有 telemetry proto 的规范目录迁移。
- 配置 lint、breaking、生成漂移和基础契约测试。

### 阶段二：首批并行模块

并行接入已有前端基础且业务闭环明确的八个模块：

- 工单管理
- SQL 窗口
- SQL 审核
- 慢 SQL 治理
- 审计日志
- 锁透视
- 结构对比
- 报告中心

### 阶段三：分析与管理模块

并行实现监控、巡检、性能洞察、根因诊断、索引推荐、会话限流、存储、参数、账号、自治、Dashboard、告警和 AI 小助手等模块。

### 阶段四：复杂编排模块

在 Job/Command/Artifact 基础稳定后实现批量执行、备份恢复和跨实例复杂编排，降低重复建设和返工风险。

## 16. 验收标准

- 前端可仅凭 OpenAPI 和 Prism 完成模块开发与交互测试。
- 后端可仅凭生成接口和 examples 完成 Handler，实现后无需修改前端 DTO。
- Agent 可在无浏览器依赖下完成能力协商、采集、命令执行、断线恢复和结果上报测试。
- 任一模块的契约变更都会触发生成漂移与 breaking 检查。
- 异步任务可从 REST Job 追踪到具体 Agent Command、Artifact 和 Audit Event。
- 权限、幂等、并发更新、错误格式和追踪字段在所有模块保持一致。
- Oracle、MySQL、MariaDB、达梦、OceanBase、HBase 及其 HDFS/ZooKeeper、Neo4j、MongoDB、TiDB、PostgreSQL、openGauss 的差异通过适配器 capability 对外呈现。
- Server 与 Agent 的 Linux 发布物可在 CentOS 7 及以上、Kylin V10 及以上运行，并通过 Windows Docker 环境中的兼容性验证流程。
