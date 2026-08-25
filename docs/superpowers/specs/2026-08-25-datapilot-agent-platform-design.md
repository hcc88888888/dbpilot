# DataPilot Agent 与多数据库运维平台设计规格

## 1. 目标与范围

第一阶段建立 DataPilot Agent 与控制面的最小可用闭环，为 Oracle、MySQL、MariaDB、达梦、OceanBase、HBase、Neo4j、MongoDB、TiDB、PostgreSQL 和 openGauss 提供统一的实例注册、心跳、基础指标采集和受控运维任务执行能力。

本阶段不实现完整 SQL 审核引擎、自治管理或 AI 根因诊断；这些能力在 Agent 协议稳定后作为上层服务接入。

## 2. 总体架构

```text
Web Portal
    │ HTTPS / WebSocket
Control Plane (Go)
    ├── Tenant / IAM
    ├── Agent Registry
    ├── Policy & Approval
    ├── Job Scheduler
    ├── Metrics / Audit API
    └── Agent Gateway (gRPC + mTLS)
             │
        DataPilot Agent (Go)
             ├── Host Collector
             ├── Database Adapters
             ├── Log Collector
             ├── Command Runtime
             └── Local Spool
```

Agent 负责靠近数据源采集和执行，Control Plane 负责租户、策略、审批、调度、审计和统一 API。指标管道遵循 OpenTelemetry 的 receiver / processor / exporter 模型，Agent 命令执行模块保持独立，避免把遥测 Collector 变成任意远程 Shell。

## 3. Agent 能力

### 3.1 采集

- 主机：CPU、内存、磁盘、网络、进程和文件系统。
- 实例：连接状态、版本、角色、容量、会话、锁、复制和错误状态。
- SQL：慢 SQL、执行次数、耗时、扫描行数、执行计划摘要。
- 日志：数据库错误日志、审计日志和慢查询日志。
- Agent 自身：版本、资源占用、队列堆积、最后成功采集时间。

### 3.2 受控执行

第一阶段只支持结构化命令，不接收任意 Shell 字符串。命令类型包括 `TEST_CONNECTION`、`COLLECT_METADATA`、`RUN_EXPLAIN`、`COLLECT_LOCK_SNAPSHOT`、`CHECK_REPLICATION`、`ANALYZE_TABLE`、`KILL_SESSION` 和 `RUN_APPROVED_SQL`。

每个任务包含目标、数据库类型、参数、超时时间、审批单号、发起人、签名和过期时间。高风险命令必须关联审批单；Agent 侧再次检查白名单、参数和本地策略。

### 3.3 安全

- Control Plane 与 Agent 双向 mTLS。
- Agent 使用一次性注册码注册，注册后轮换证书。
- 任务使用服务端签名、唯一 ID 和过期时间，防重放。
- Agent 以低权限用户运行，限制 CPU、内存、输出大小和执行时长。
- 所有任务记录请求、审批、执行、输出摘要和结果码。
- 默认拒绝任意 Shell；必要的脚本必须经过签名、审批和沙箱策略。
- 断网时仅允许本地安全采集，恢复连接后上传缓存；不允许离线执行高风险命令。

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
```

Adapter 分为连接、元数据、指标、操作和审计五个能力域。数据库可只实现部分能力，Control Plane 通过 capability matrix 显示可用项，不把 HBase、Neo4j、MongoDB 强行映射为传统 SQL 数据库。

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

- Agent：Go，单二进制，Linux / Windows，gRPC、Protobuf、SQLite spool。
- Control Plane：Go，REST + gRPC，PostgreSQL 保存控制面数据。
- 任务队列：NATS JetStream；需要大规模日志流时再引入 Kafka。
- 指标：VictoriaMetrics 或 Prometheus Remote Write。
- 审计与 SQL 样本：ClickHouse；对象和报告：MinIO。
- 可视化：现有前端逐步替换为 React + TypeScript，指标图表嵌入 Grafana 或使用 Grafana API。
- 遥测：OpenTelemetry Collector / Grafana Alloy；命令执行保持为 DataPilot 自研 Runtime。

## 7. 失败处理与可观测性

- 采集失败按 Adapter、实例、指标粒度记录，不因单个实例故障阻塞整个 Agent。
- 任务支持指数退避、最大重试次数和幂等键。
- 每条任务必须有 trace ID，关联 Agent 日志、控制面日志和审计事件。
- Agent 通过本地健康端点暴露连接、队列、采集延迟和资源使用情况。
- 配置下发采用版本号与 ACK；Agent 不接受降级到未签名配置。

## 8. 验收标准

1. Agent 可注册、心跳、证书认证和安全注销。
2. Control Plane 可展示 Agent、实例和 capability matrix。
3. 至少 MySQL、PostgreSQL 和 Oracle 完成连接测试、基础指标、元数据和 Explain。
4. 任务可创建、审批、下发、执行、取消、重试和审计。
5. Agent 离线后能够缓存指标，恢复后补传，且不会执行高风险离线任务。
6. 任意命令执行都能通过 job ID 查询完整生命周期。

## 9. 后续阶段

Agent 闭环稳定后，再接入 SQLFluff / SQLGlot 规则服务、PMM Query Analytics、CloudBeaver SQL 工作台、巡检策略、报告中心、DB-GPT Agent 和自治能力。锁回放、索引自治和跨模块根因诊断作为独立设计，不与 Agent 基础协议耦合。
