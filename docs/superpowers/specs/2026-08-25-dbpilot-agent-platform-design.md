# DBPilot Agent 与多数据库运维平台设计规格

> 状态：待书面复核（聊天设计已确认）
> 更新日期：2026-08-26

## 1. 目标与范围

第一阶段建立 DBPilot Agent 与控制面的最小可用闭环，为 Oracle、MySQL、MariaDB、达梦、OceanBase、HBase、Neo4j、MongoDB、TiDB、PostgreSQL 和 openGauss 提供统一的实例注册、心跳、基础指标、数据库与操作系统日志、自定义文件、自定义指标和受控运维任务执行能力。

本阶段不实现完整 SQL 审核引擎、自治管理或 AI 根因诊断；这些能力在 Agent 协议稳定后作为上层服务接入。

## 2. 总体架构

```text
Web Portal（React + TypeScript）
    │ HTTPS / WebSocket
Control Plane（Go，模块化单体起步）
    ├── Tenant / IAM / Policy
    ├── Agent Registry
    ├── Workflow / Approval / Audit
    ├── Job Scheduler
    ├── Log Ingest Gateway
    ├── Metrics Ingest Gateway
    └── Agent Gateway（gRPC + mTLS）
             │ Agent 主动出站连接
        DBPilot Agent（Go，单进程单二进制）
             ├── Identity & Control Client
             ├── Database Adapters
             ├── Telemetry Engine
             ├── Typed Command Runtime
             ├── Policy Compiler
             └── Local State & Spool
```

Agent 负责靠近数据源采集和执行，Control Plane 负责租户、策略、审批、调度、审计和统一 API。Agent 不携带、不启动也不暴露独立 Vector 进程；Vector 仅作为采集语义和可靠性设计参考。采集内核复用 OpenTelemetry Collector 的 Go 组件并整合进 `dbpilot-agent`，遵循 receiver / processor / exporter 模型。命令执行模块与遥测管道在代码和权限上隔离，避免把采集引擎变成任意远程 Shell。

## 3. Agent 能力

### 3.1 统一采集范围

- 主机指标：CPU、Load、内存、Swap、磁盘、inode、IO、网络、进程、cgroup 和文件系统。
- 数据库指标：连接状态、版本、角色、容量、会话、锁、复制、错误状态和数据库专属指标。
- SQL 指标：慢 SQL、执行次数、耗时、扫描行数和执行计划摘要。
- 数据库日志：错误日志、审计日志、慢查询日志、监听日志和数据库专属运行日志。
- 操作系统日志：journald、messages、secure、audit、cron、kernel 和指定 systemd unit。
- 自定义文件日志：路径/glob、编码、轮转、多行、解析、过滤、采样、限速和保留策略。
- 自定义指标：Prometheus Scrape、HTTP/JSON、只读 SQL 指标和签名采集插件。
- Agent 自身：版本、资源占用、采集延迟、丢弃量、队列堆积、配置版本和最后成功时间。

### 3.2 内置 Telemetry Engine

```text
Receivers
  ├── Database Metrics（DBPilot 自研）
  ├── Host Metrics
  ├── File Log
  ├── Journald
  ├── Prometheus Scrape
  └── Custom Metrics（DBPilot 自研安全封装）
         │
Processors
  ├── Parse / Multiline
  ├── Filter / Transform / Enrich
  ├── Cardinality Guard
  ├── Batch / Rate Limit
  └── Memory Limiter
         │
Persistent Queue
         │
DBPilot Log / Metrics Exporter（mTLS + ACK）
```

优先复用 OpenTelemetry Collector 的 `filelog`、`journald`、`hostmetrics`、`prometheus`、`batch`、`memory_limiter`、`filter` 和 `transform` 组件。DBPilot 自研数据库 Receiver、策略编译器、Exporter、持久队列和能力注册。Server 不下发原始 OTel、Vector 或 Shell 配置，只下发 DBPilot 自有、受限、带签名和版本的采集策略。

### 3.3 自定义采集安全边界

- 自定义日志路径必须位于 Agent 允许目录中；解析真实路径后禁止软链接逃逸，并默认拒绝 `/proc`、`/sys` 和凭据目录。
- 配置限制文件数量、单行大小、事件速率、内存和磁盘占用；候选管道验证成功后才能原子切换，失败时保留上一版本。
- Prometheus 和 HTTP 指标仅允许策略声明的地址、TLS 和认证方式，并限制标签数量及基数。
- SQL 指标只允许单条只读查询，使用低权限账号，强制超时、频率和最大结果行数。
- 命令指标不得接受任意 Shell；只允许已注册、签名且参数受控的采集插件。

### 3.4 日志可靠性

- 文件日志使用 fingerprint、offset 和 checkpoint 识别轮转与截断，服务端确认批次后才推进可清理游标。
- 日志和指标进入分段磁盘队列，支持断网恢复、批量压缩、校验和、容量上限和优先级。
- bbolt 仅保存配置、checkpoint、批次索引和任务去重；大块日志和指标正文保存为 spool segment，避免键值库膨胀。
- 审计日志不得静默丢弃；达到容量或权限异常时必须产生 Agent 健康告警。
- 日志发送至 DBPilot Log Ingest Gateway，指标发送至 Metrics Ingest Gateway；Agent 不持有 ClickHouse、VictoriaMetrics 或对象存储中心凭据。

### 3.5 受控执行

第一阶段只支持结构化命令，不接收任意 Shell 字符串。命令类型包括 `TEST_CONNECTION`、`COLLECT_METADATA`、`RUN_EXPLAIN`、`COLLECT_LOCK_SNAPSHOT`、`CHECK_REPLICATION`、`ANALYZE_TABLE`、`KILL_SESSION` 和 `RUN_APPROVED_SQL`。

每个任务包含目标、数据库类型、参数、超时时间、审批单号、发起人、签名和过期时间。高风险命令必须关联审批单；Agent 侧再次检查白名单、参数和本地策略。

### 3.6 安全

- Control Plane 与 Agent 双向 mTLS。
- Agent 使用一次性注册码注册，注册后轮换证书。
- 任务使用服务端签名、唯一 ID 和过期时间，防重放。
- Agent 以低权限用户运行，限制 CPU、内存、输出大小和执行时长。
- 所有任务记录请求、审批、执行、输出摘要和结果码。
- 默认拒绝任意 Shell；必要的脚本必须经过签名、审批和沙箱策略。
- 断网时仅允许本地安全采集，恢复连接后上传缓存；不允许离线执行高风险命令。

### 3.7 Linux 与国产化兼容

- Server 与 Agent 支持 Linux amd64，目标系统为 CentOS 7+ 和麒麟 V10+；Agent 同时支持 Linux arm64 以覆盖麒麟 ARM 环境。
- 使用 Go 静态构建，默认 `CGO_ENABLED=0` 和 `GOAMD64=v1`，不依赖目标机动态 C 运行库。
- 以 systemd 服务和普通低权限用户运行；journald 通过 `systemd-journal` 组或 ACL 获得最小读取权限。
- 发布流水线必须完成 Linux amd64/arm64 交叉编译，并在真实 CentOS 7、麒麟 V10 x86_64/arm64 环境执行安装、启动、日志读取、断网恢复和升级冒烟测试。
- 中心基础组件不承诺部署在 CentOS 7；PostgreSQL、VictoriaMetrics、ClickHouse 和对象存储应部署在各自受支持的现代 Linux 或容器平台。

## 4. 数据库 Adapter 接口

```go
type DatabaseAdapter interface {
    TestConnection(ctx context.Context) error
    GetInstanceInfo(ctx context.Context) (InstanceInfo, error)
    CollectMetrics(ctx context.Context) ([]Metric, error)
    CollectSessions(ctx context.Context) ([]Session, error)
    CollectLocks(ctx context.Context) ([]LockEvent, error)
    CollectMetadata(ctx context.Context) (Metadata, error)
    Explain(ctx context.Context, sql string) (Plan, error)
    Execute(ctx context.Context, req OperationRequest) (OperationResult, error)
}

type LogSourceProvider interface {
    DefaultLogSources(ctx context.Context) ([]LogSourceSpec, error)
}

type CustomMetricCollector interface {
    CollectCustomMetrics(ctx context.Context, spec MetricCollectionSpec) ([]Metric, error)
}
```

Adapter 分为连接、元数据、指标、日志源、操作和审计能力域。数据库可只实现部分能力，Control Plane 通过 capability matrix 显示可用项，不把 HBase、Neo4j、MongoDB 强行映射为传统 SQL 数据库。日志读取本身由 Telemetry Engine 完成，Adapter 只提供数据库类型对应的默认路径、格式和解析模板；SQL 自定义指标通过受限的 `CustomMetricCollector` 执行。

首批 Adapter 顺序：MySQL / PostgreSQL → Oracle / MongoDB / TiDB → MariaDB / OceanBase / openGauss → 达梦 / HBase / Neo4j。

## 5. 核心数据模型

- `tenants`：租户与项目边界。
- `agents`：Agent 身份、证书、版本、主机和状态。
- `instances`：数据库实例、类型、连接引用和 capability matrix。
- `metric_samples`：标准化指标、标签、时间和值。
- `jobs`：结构化运维任务、状态机和重试策略。
- `job_approvals`：审批人、审批决策和时间。
- `audit_events`：不可变的操作审计记录。
- `agent_configs`：版本化采集配置和下发状态。

任务状态机：`PENDING → APPROVING → DISPATCHED → RUNNING → SUCCEEDED / FAILED / CANCELED / EXPIRED`。

## 6. 推荐技术栈

- Agent：Go，单进程单二进制，gRPC、Protobuf、OpenTelemetry Collector Go 组件、bbolt 元数据和 segment spool。
- Control Plane：Go 模块化单体起步，REST/OpenAPI + gRPC，PostgreSQL 保存控制面数据。
- 任务调度：第一阶段使用 PostgreSQL 任务表、Outbox 和 Worker；出现明确吞吐或解耦需求后再引入 NATS JetStream。
- 指标：VictoriaMetrics；Agent 通过 DBPilot Metrics Gateway 写入，不直连存储。
- 日志、审计与 SQL 样本：启用日志能力时使用 ClickHouse；原始日志和报告写入企业 S3，对象存储缺失时再部署 MinIO。
- 可视化：现有前端逐步替换为 React + TypeScript，指标图表嵌入 Grafana 或使用 Grafana API。
- 遥测：在 Agent 内嵌 OpenTelemetry Collector Go 组件构建 DBPilot Telemetry Engine；Vector 只作为设计参考；命令执行保持为 DBPilot 自研 Runtime。

## 7. 失败处理与可观测性

- 采集失败按 Receiver、Adapter、实例和数据源粒度记录，不因单个实例或文件故障阻塞整个 Agent。
- 任务支持指数退避、最大重试次数和幂等键。
- 每条任务必须有 trace ID，关联 Agent 日志、控制面日志和审计事件。
- Agent 健康信息通过已认证的控制通道上报连接、管道、队列、采集延迟、丢弃量和资源使用；默认不对外开放本地管理端口。
- 配置下发采用版本号与 ACK；Agent 不接受降级到未签名配置。

## 8. 验收标准

1. Agent 可注册、心跳、证书认证和安全注销。
2. Control Plane 可展示 Agent、实例和 capability matrix。
3. 至少 MySQL、PostgreSQL 和 Oracle 完成连接测试、基础指标、元数据和 Explain。
4. 任务可创建、审批、下发、执行、取消、重试和审计。
5. Agent 离线后能够缓存指标，恢复后补传，且不会执行高风险离线任务。
6. 任意命令执行都能通过 job ID 查询完整生命周期。
7. Agent 能采集 journald、操作系统日志和自定义文件日志，并正确处理轮转、多行、checkpoint 和断网恢复。
8. Agent 能采集主机指标、Prometheus 指标和受控自定义指标，并阻断任意 Shell 形式的采集配置。
9. 同一 Agent 二进制通过 CentOS 7、麒麟 V10 x86_64 和麒麟 V10 arm64 兼容测试。

## 9. 后续阶段

Agent 闭环稳定后，再接入 SQLFluff / SQLGlot 规则服务、PMM Query Analytics、CloudBeaver SQL 工作台、巡检策略、报告中心、DB-GPT Agent 和自治能力。锁回放、索引自治和跨模块根因诊断作为独立设计，不与 Agent 基础协议耦合。
