# DBPilot 主机与数据库插件管理平台设计

日期：2026-08-30  
状态：已完成方案讨论，待用户审阅规格后进入实施计划  
目标分支：`codex/host-database-plugin-platform-design`

## 1. 背景

DBPilot 已具备以下经过验证的基础：

- Linux Agent、控制面与 PostgreSQL 的运行闭环。
- Agent mTLS/SPIFFE 身份、Hello/Heartbeat、断线重连与本地 spool。
- 签名策略、主机指标、文件日志、journald、Prometheus 和 HBase/HDFS/ZooKeeper JMX 采集。
- PostgreSQL Job/Outbox、Prepare → Start 两阶段命令、Agent bbolt journal 和 ResultAck。
- OIDC、项目级权限、Artifact、Audit、基础监控与主机巡检。
- Kylin V10 SP1 amd64、Docker Compose、真实浏览器和 PostgreSQL 的全栈验收环境。

当前数据库 Adapter 主要停留在独立库和测试边界。MySQL/PostgreSQL 协议 Adapter、Oracle/达梦 Factory 和 HBase 组件 Adapter 已存在，但 SQL 数据库 Adapter 尚未统一接入 Agent 的实例纳管、插件生命周期、模板下发和运行时采集。前端已有多个原生 JavaScript 模块，但主机、实例、插件、模板审批等复杂管理页面尚不存在。

本设计建立下一阶段的核心平台能力：先纳管主机，自动发现数据库候选，确认后纳管数据库实例；数据库采集以独立插件进程扩展，并由 Server 统一管理部署、启停、升级和回滚。

## 2. 已确认的架构决策

以下决策在讨论中已明确确认：

1. 第一阶段必须形成 Agent → Server 的真实闭环，同时展示主机指标和至少一种数据库指标。
2. 第一款数据库插件为 MySQL，首批支持五项真实指标。
3. 每台 Agent、每种数据库插件类型最多一个活动插件进程；单个插件服务本机多个实例。
4. 没有对应实例绑定时，不运行该数据库插件。
5. 插件包统一上传并托管在 DBPilot Server，Agent 不访问公网插件源。
6. Server 保存插件期望状态，Agent 负责本机调谐。
7. 自定义指标模板采用草稿 → 静态校验 → 目标实例试运行 → 人工审批 → 发布流程。
8. 主机先于数据库实例纳管；主机纳管后自动发现数据库进程和 Docker 容器。
9. 第一版发现范围覆盖 Linux 原生进程和 Docker 容器，不包含 Kubernetes。
10. Docker 发现使用独立、受限的 `dbpilot-docker-discovery` 辅助进程；Agent 和数据库插件不得直接持有原始 Docker Socket。
11. 前端采用 React + TypeScript + Vite 渐进迁移，既有页面暂时兼容挂载。
12. Server 暂不改用 Gin/Echo/Chi；新模块强制使用 OpenAPI、Application Service、Domain、Repository 的框架无关分层。

## 3. 目标

### 3.1 产品目标

- 提供主机注册、状态、标签、资源和 Agent 生命周期管理。
- 在主机纳管后自动发现原生进程和 Docker 容器中的数据库候选。
- 允许管理员以较少输入确认候选并纳管数据库实例。
- 提供 Server 端插件仓库、版本、分配、部署、启停、升级、回滚和状态查看。
- Agent 以插件 Supervisor 管理数据库插件，不把插件逻辑编译进 Agent 核心。
- 一个 MySQL 插件进程管理同一 Agent 主机上的多个 MySQL 实例。
- 复用现有 spool、mTLS 和 TelemetryIngest，将数据库指标规范化后上报 Server。
- 为每类数据库提供独立内置指标模板目录，并支持有审批的自定义模板。
- 以 React 页面管理主机、候选、实例、插件和模板。
- 保持现有主机巡检、基础监控、告警和 Agent 命令闭环不回归。

### 3.2 技术目标

- 插件协议稳定、版本化、可测试，并与 Web 框架无关。
- 数据库驱动、依赖和故障隔离在插件进程内。
- Server 和 Agent 通过声明式 desired/observed state 收敛，不依赖一次性命令的偶然成功。
- 插件安装、升级和回滚是可重试、幂等、可审计的。
- 明文凭据不进入 PostgreSQL Job/Outbox、Audit、日志、命令行、环境变量或插件磁盘。
- CentOS 7+ 和 Kylin V10+ linux/amd64 使用静态或明确兼容的插件二进制。

## 4. 非目标

第一阶段明确不包含：

- PostgreSQL、Oracle、达梦、MongoDB、Neo4j 等第二种数据库插件。
- Kubernetes Pod/Operator/DaemonSet 发现和管理。
- 同一 Agent 主机跨 tenant/project 共享纳管；第一阶段一个 Agent 仍映射一个 tenant/project。
- 插件直接访问 DBPilot Server。
- Server 或 Agent 创建、删除、启动、停止业务 Docker 容器。
- 任意 shell、任意二进制执行或任意 SQL 采集。
- 自动修复数据库、自动执行参数调优或索引 DDL。
- 全量迁移现有原生 JavaScript 页面。
- Server 微服务化或 Gin/Echo 框架迁移。
- PostgreSQL TLS、外部 Secret Manager、HA、负载、长稳和真实 Kylin VM/bare-metal 发布认证；这些保留为生产发布门禁。

## 5. 总体架构

```text
DBPilot Server
├── Host Inventory
├── Discovery Candidate Service
├── Database Instance Registry
├── Plugin Catalog / Version / Artifact
├── Plugin Assignment / Reconciler
├── Metric Template Workflow
├── Credential Lease Service
├── Job / Command / Artifact / Audit
└── Monitoring / Alert / Inspection
          │
          │ mTLS gRPC + signed typed commands
          ▼
DBPilot Agent
├── Host Collector
├── Native Discovery Engine
├── Docker Discovery Client
├── Plugin Supervisor
├── Plugin Artifact Cache + A/B Slots
├── Local Plugin Gateway (Unix Socket/gRPC)
├── Metric Normalizer
├── Spool / Exporter
└── Command Journal
          │
          ├── dbpilot-plugin-mysql       one process, N instances
          ├── dbpilot-plugin-postgresql  later
          └── dbpilot-plugin-oracle      later

Docker hosts only:
dbpilot-docker-discovery
└── restricted Docker Engine API reads
```

浏览器只访问 Server。插件只访问被授权的数据库实例和 Agent 本机 Unix Socket。Docker Discovery Helper 只访问 Docker Engine 和 Agent 本机 Unix Socket。任何插件或 Helper 都不直接访问 Server API。

## 6. 信任边界

### 6.1 Server 信任

Server 信任：

- 经 OIDC 验证并具有项目权限的管理员。
- 经 mTLS/SPIFFE 验证的 Agent。
- 经批准发布者 Ed25519 签名验证的插件包。
- 经审批发布并由 Server 签名的指标模板 revision。

Server 不信任：

- Agent 或插件载荷中的租户、项目、主机和实例归属字段。
- 浏览器传入的 scope 覆盖。
- 插件自报的二进制路径、版本或能力，除非与 assignment 和 manifest 匹配。
- Docker 标签、镜像名和命令行中的凭据或未经脱敏的数据。

### 6.2 Agent 信任

Agent 只接受：

- 现有控制面公钥签名的类型化命令。
- Server Artifact 能力提供的短期插件下载地址。
- 发布者签名和 SHA-256 均匹配的插件包。
- 单调递增的 assignment/configuration revision。
- 位于 Agent 私有插件根目录中的非 symlink 固定二进制。
- 由 Agent 启动、Unix peer credentials 匹配、握手 nonce 匹配的插件进程。

Agent 不执行插件 manifest 中的安装脚本、shell、post-install hook 或任意命令。

## 7. 主机纳管

### 7.1 主机身份

主机纳管使用一次性 Enrollment Token。Server 创建 `host_id` 和预期 enrollment，Agent 使用 token 交换长期 mTLS 证书。证书 SPIFFE 身份绑定 `agent_id`；Server 的 inventory 映射绑定 tenant/project/host。

hostname、IP、machine-id 或 Docker 节点名只用于展示和重复提示，不是授权身份。

### 7.2 ManagedHost

```text
ManagedHost
├── host_id
├── agent_id
├── tenant_id
├── project_id
├── display_name
├── hostname
├── operating_system
├── operating_system_version
├── kernel_version
├── architecture
├── cpu_summary
├── memory_summary
├── filesystem_summary
├── network_addresses
├── labels
├── container_runtime
├── agent_version
├── enrollment_revision
├── enrolled_at
├── last_hello_at
├── last_heartbeat_at
└── status
```

状态集合：

```text
pending → enrolling → online → stale → offline → decommissioned
```

- `online` 需要真实 AgentControl Heartbeat。
- `stale` 表示超过健康窗口但尚未达到 offline 窗口。
- `decommissioned` 需要显式管理员操作，Agent 证书随后撤销。

### 7.3 主机能力

Agent 上报：

- Host Collector 能力。
- Native Discovery 版本和规则 revision。
- Docker Discovery Helper 是否存在、版本、健康和能力。
- Plugin Supervisor 协议版本、支持的包格式和平台。
- 已安装插件的 observed 摘要。

Server 的 capability matrix 必须诚实显示缺失原因，例如：

- `agent_unsupported`
- `docker_discovery_unavailable`
- `plugin_not_installed`
- `plugin_version_incompatible`
- `permission_denied`

## 8. 数据库自动发现

### 8.1 发现时机

- Agent enrollment 成功后立即扫描一次。
- Native Discovery 默认每 5 分钟扫描，可由签名策略在 1 分钟至 1 小时范围内调整。
- Docker Discovery 订阅容器 start/stop/die/destroy 事件，并每 5 分钟完整校准。
- Server 可通过 `DiscoverDatabases` 类型化命令触发立即扫描。
- 同一 revision 的重复结果必须幂等。

### 8.2 Native Discovery

Agent 核心读取：

- `/proc/<pid>/exe`、允许的 cmdline 字段、uid、start time 和 cgroup。
- systemd D-Bus 的 service 名称和 active state。
- `/proc/net` 或安全系统 API 提供的监听地址、端口和 Unix Socket。
- 经签名发现规则允许的可执行路径、进程名、service 名和默认端口。

Agent 禁止：

- 为发现执行任意 shell。
- 运行未注册数据库二进制的任意参数。
- 读取进程环境变量明文。
- 读取数据库配置中的密码、token 或完整连接串。
- 上传完整 cmdline；只上报字段白名单和脱敏结果。

### 8.3 Docker Discovery

`dbpilot-docker-discovery` 是每台 Docker 主机最多一个的可选系统组件，不是数据库插件。它仅在主机 enrollment 时本地管理员明确启用 Docker 发现后运行。

由于 Docker Socket 是宿主机高权限边界，Server 不远程自动安装或授权该 Helper。主机管理员必须在 enrollment 前安装并启用它；Server 只能管理发现开关和展示 observed 状态。选择 Docker 发现但 Helper 不可用时，主机仍可完成原生进程纳管，但 Docker discovery capability 显示 `docker_discovery_unavailable`。

Helper 可读取：

- `/containers/json`
- `/containers/{id}/json`
- `/events`
- `/info` 的必要只读字段

它只向 Agent 暴露：

- container ID/name/image/status。
- 端口映射。
- 允许的标签。
- Entrypoint/Cmd 脱敏摘要。
- 宿主 PID 和 cgroup 关联。
- start/stop/die/destroy 事件。

Helper 禁止转发或实现：

- Docker POST/PUT/PATCH/DELETE。
- exec、attach、logs、archive、stats 原始流。
- 容器环境变量明文。
- Volume 文件读取。
- 网络、镜像、容器和 Volume 修改。

Agent、数据库插件和 Server 不得直接挂载原始 Docker Socket。Helper 的 systemd 服务必须使用只读根文件系统、NoNewPrivileges、PrivateTmp、ProtectSystem、ProtectHome、能力清零和有界资源。Helper 持有 Docker Socket 仍属于高权限边界，生产发布前必须单独进行威胁建模和主机加固审查。

### 8.4 DiscoveryRuleSet

Server 版本化并签名发现规则：

```text
DiscoveryRule
├── rule_id
├── version
├── database_family
├── database_variant
├── process_names
├── executable_path_patterns
├── systemd_units
├── default_ports
├── unix_socket_patterns
├── docker_image_patterns
├── docker_label_selectors
├── version_extractors
└── confidence_weights
```

规则表达式必须兼容 Go RE2，不允许回溯型正则。规则只能描述只读匹配，不允许携带命令、脚本、SQL 或文件内容读取操作。

### 8.5 DatabaseCandidate

```text
DatabaseCandidate
├── candidate_id
├── tenant_id / project_id
├── host_id / agent_id
├── discovery_source: native | docker
├── database_family
├── database_variant
├── version_hint
├── normalized_endpoint
├── unix_socket
├── process_identity
├── service_name
├── container_identity
├── container_image
├── discovered_role
├── confidence
├── evidence_summary
├── fingerprint
├── rule_revision
├── first_seen_at / last_seen_at
└── status
```

候选状态：

```text
discovered → awaiting_confirmation → accepted → provisioning
            ↘ ignored
            ↘ duplicate
            ↘ disappeared
```

`evidence_summary` 只能包含固定枚举和脱敏后的短字段，不保留完整命令行、环境变量或配置正文。

### 8.6 去重

指纹由以下规范化事实构成：

```text
host_id
+ database_family
+ normalized endpoint 或 Unix Socket
+ native service identity 或 container identity
```

PID 不能作为稳定身份。容器重建、进程重启后，若 endpoint 和实例身份仍一致，应关联原候选；证据不足时标记 `possible_duplicate`，不得自动合并。

## 9. 数据库实例纳管

### 9.1 ManagedDatabaseInstance

```text
ManagedDatabaseInstance
├── instance_id
├── tenant_id / project_id
├── host_id / agent_id
├── database_family
├── database_variant
├── display_name
├── endpoint / unix_socket
├── version / edition
├── role / topology
├── credential_ref
├── tls_ref
├── plugin_id / desired_plugin_version
├── template_profile_id
├── labels
├── capability_matrix
├── connection_test_status
├── connection_test_at
├── plugin_assignment_revision
└── management_status
```

状态：

```text
accepted
→ provisioning
→ connection_testing
→ managed
→ monitoring
```

失败或退出：

```text
provisioning       → plugin_failed
connection_testing → authentication_failed | tls_failed | unreachable | unsupported_version
managed            → degraded | offline | retired
```

### 9.2 接受候选

管理员接受候选时：

1. 确认数据库 family/variant、endpoint、名称和标签。
2. 选择或创建 `credential_ref` 与 `tls_ref`。
3. Server 创建实例和 plugin assignment，事务中记录 Audit 与 idempotency response。
4. Reconciler 创建 `ReconcilePlugin` Job。
5. Agent 安装/启动插件并应用实例配置 revision。
6. 插件执行 `ValidateInstance`。
7. 成功后实例进入 `managed` 并启用模板 profile。
8. 失败保留候选、实例和固定错误码，不泄漏驱动错误或凭据。

接受第二个 MySQL 候选时，Server 必须复用同一 Agent 上已有的 MySQL plugin assignment，只增加实例配置，不创建第二个 MySQL 插件进程。

## 10. 插件包与插件仓库

### 10.1 包格式

第一阶段使用确定性的 `.tar.gz` 包：

```text
plugin-package/
├── manifest.json
├── bin/linux-amd64/dbpilot-plugin-mysql
├── bin/linux-arm64/dbpilot-plugin-mysql
├── schemas/config.schema.json
├── templates/catalog.json
├── LICENSES/
└── SIGNATURE.ed25519
```

`manifest.json` 包含：

- plugin ID、database family、版本和协议版本。
- 发布者 ID 和签名 key ID。
- 每个平台二进制路径、SHA-256 和大小。
- 最低/最高 Agent 协议版本。
- 支持的数据库 variant/版本范围。
- 能力矩阵和指标模板 Schema 版本。
- 包内容文件清单和哈希。

禁止脚本、动态库搜索路径覆盖、post-install hook 和外部下载声明。

### 10.2 签名

- 发布者 Ed25519 签名覆盖 canonical manifest 和完整包 SHA-256。
- Server 上传时验证签名、路径规范化、重复文件、symlink、文件数量和解压大小。
- Agent 下载后独立重复验证，不能只信任 Server 的 `verified` 状态。
- Artifact 下载 HMAC 只表示短期下载授权，不替代发布者签名。
- 被撤销版本不能新部署；已运行实例进入 `revoked_running`，由管理员按风险策略升级或停止。

### 10.3 插件版本状态

```text
uploaded → verified → approved → available → deprecated → revoked
          ↘ rejected
```

只有 `available` 版本可用于新 assignment。`approved` 到 `available` 需要具有插件发布权限的管理员操作。

## 11. Server desired state 与 Agent observed state

### 11.1 PluginAssignment

```text
PluginAssignment
├── assignment_id
├── host_id / agent_id
├── plugin_id
├── database_family
├── desired_version
├── desired_state: absent | installed | running | stopped
├── configuration_revision
├── operation_revision
├── rollout_policy
├── created_at / updated_at
└── etag
```

### 11.2 PluginObservedState

```text
PluginObservedState
├── assignment_id
├── installed_version
├── active_slot
├── process_state
├── pid
├── started_at
├── health
├── restart_count
├── circuit_state
├── bound_instance_count
├── active_configuration_revision
├── observed_operation_revision
├── last_error_code
└── observed_at
```

Server Reconciler 比较 desired 与 observed：

- revision 一致且状态匹配时不下发命令。
- desired revision 更高时创建一次幂等 Job。
- Agent 上报高于 Server 已知 revision 时标记 `state_conflict`，不得回退覆盖。
- 过期 Agent observed state 不触发重复安装；先等待 Agent online 或由管理员强制修复。

### 11.3 类型化命令

新增 Agent v1 命令：

- `DiscoverDatabases`
- `ReconcilePlugin`
- `ApplyPluginConfiguration`
- `ValidateDatabaseInstance`
- `DrainPlugin`
- `CollectDatabaseMetrics`

`ReconcilePlugin` 包含：

```text
plugin_id
database_family
desired_version
desired_state
artifact_id
artifact_sha256
manifest_digest
configuration_revision
operation_revision
```

命令中只保存 Artifact ID、公开 digest 和 desired state，不保存短期下载 URL 或下载签名。Agent 在 Start fence 生效后，通过已认证 AgentControl stream 请求一次短期 `PluginArtifactLease`，再从 Server 下载包。

命令继续使用现有 Prepare → Start、execution token、lease revision、Cancel、Result 和 ResultAck。不得新增任意 shell 或任意 executable 命令。

## 12. Agent Plugin Supervisor

### 12.1 文件布局

```text
/var/lib/dbpilot-agent/plugins/
└── mysql/
    ├── versions/
    │   ├── 1.0.0/
    │   └── 1.1.0/
    ├── active -> versions/1.1.0
    ├── runtime/
    │   ├── plugin.sock
    │   └── state.json
    └── cache/
```

- 根目录 0700，归 Agent 非 root 用户所有。
- 插件二进制 0500，manifest 0400。
- active 只能指向经过验证的 versions 子目录。
- 禁止 symlink 穿越、硬链接逃逸和跨文件系统 rename 假设。
- 下载使用 create-exclusive 临时文件、fsync、校验和原子 rename。
- 第一阶段插件与 Agent 使用同一个非 root OS 用户，但每个插件目录相互隔离；插件不得以 root 身份运行。

### 12.2 进程粒度

- 每个 Agent、每个 `database_family` 最多一个活动插件进程。
- MySQL、MariaDB、TiDB、OceanBase 可在未来声明为同一个 MySQL protocol plugin family 的 variant，但第一阶段只对 MySQL variant 提供生产证据。
- 同一插件内按实例隔离连接池、采集队列、超时、并发、熔断和模板集合。
- 单个实例失败不能导致插件退出。

### 12.3 Supervisor 状态机

```text
absent
→ downloading
→ verifying
→ installed
→ starting
→ handshaking
→ running
```

异常：

```text
downloading → download_failed
verifying   → signature_rejected | manifest_rejected | platform_mismatch
starting    → start_failed | handshake_failed
running     → degraded → restarting → circuit_open
upgrading   → rollback
```

停止：

```text
running → draining → stopped → uninstalling → absent
```

### 12.4 重启与熔断

- 进程意外退出后使用有界指数退避。
- 10 分钟内连续 5 次失败进入 `circuit_open`。
- circuit open 后不自动无限拉起，Server 产生插件故障告警。
- 新 assignment revision、管理员 reset 或冷却期结束可触发半开探测。
- Agent 自身重启后从本地 state 和 Server desired state 重建插件进程。

### 12.5 A/B 升级

1. 下载并验证 inactive slot 新版本。
2. 运行离线 manifest/self-test，不连接生产实例。
3. 对插件发起 Drain，等待有界采集完成。
4. 停止旧进程，切换 active。
5. 启动新版本并完成 Handshake。
6. 应用相同 configuration revision。
7. 依次验证每个实例连接和一轮指标采集。
8. 任一步失败切回旧 slot 并恢复连接池。
9. 上报 rollback 原因固定码。

生产插件升级默认需要人工批准。Server 支持按单台 Agent、主机标签和百分比灰度，不默认全量升级。

## 13. Agent 与插件本机协议

### 13.1 协议位置

```text
contracts/protobuf/plugin/v1/
├── plugin.proto
├── instance.proto
├── metrics.proto
└── health.proto
```

协议只监听 Agent 私有 runtime 目录中的 Unix Socket，不监听 TCP。

插件进程是本机 gRPC Server，Agent 是唯一 client。Agent 启动插件时传入固定 socket/runtime 路径；插件创建 mode 0600 的 socket。Agent 调用 Handshake、ApplyConfiguration、ValidateInstance、CollectNow、GetHealth 和 Shutdown，并通过 `StreamMetrics` server-stream 接收插件指标。

### 13.2 PluginControl

```text
PluginControl
├── Handshake
├── ApplyConfiguration
├── ValidateInstance
├── CollectNow
├── StreamMetrics
├── GetHealth
└── Shutdown
```

### 13.3 Handshake

插件必须返回：

- plugin ID、database family、version、protocol version。
- 支持的 variants 和数据库版本范围。
- capability matrix。
- metric template Schema 版本。
- executable digest。
- launch nonce 的响应证明。

Agent 校验：

- Unix Socket 位于预期私有目录且 mode 0600。
- Linux `SO_PEERCRED` 的 PID/UID 与启动进程匹配。
- `/proc/<pid>/exe` 指向当前 active slot 的已验证二进制。
- executable digest 与 manifest 匹配。
- launch nonce 通过继承的匿名 pipe/FD 传递，不放入 argv 或环境变量。

插件可执行文件只来自受信发布者签名包。第一阶段 Agent 通过 endpoint allowlist、资源限额和进程目录约束插件，但不能在非 root 用户态完全强制网络 egress。生产部署必须同时使用主机防火墙/cgroup/systemd 限制插件只访问已纳管数据库 endpoint；该限制是发布门禁，不得把“插件代码约定”宣称为网络隔离证据。

### 13.4 ApplyConfiguration

配置是完整 revision，不是任意 patch：

- assignment 和 configuration revision 必须单调递增。
- 插件在内存中验证全部实例和模板后原子切换。
- 失败保留旧配置并返回固定错误码。
- Agent 不把明文凭据写入配置文件或 state.json。

### 13.5 MetricBatch

插件输出 DBPilot canonical DTO：

```text
MetricBatch
├── plugin_id / plugin_version
├── database_family / variant
├── instance_id
├── configuration_revision
├── template_id / template_revision
├── collected_at
├── sequence
├── samples[]
└── collection_status
```

Sample 只包含：

- canonical metric name。
- numeric value。
- fixed unit/type。
- bounded labels。
- sampled_at。

插件不能在 MetricBatch 中声明 tenant/project/host/agent 的授权归属。Agent 根据已验证 assignment 补充这些字段并写入现有 spool。

## 14. 凭据租约

### 14.1 基本原则

- Server 数据模型只保存 `secret://provider/name` 引用。
- Job、Command、Outbox、Audit 和插件 assignment 不保存明文。
- Agent 在需要连接时通过现有 mTLS 控制通道请求短期 lease。
- Secret 响应不进入通用请求/响应日志、持久化幂等快照或失败 Artifact。
- Agent 只在内存保存 lease，并通过私有 Unix Socket 传给插件。
- 插件只在内存和数据库驱动连接池中使用凭据。
- 进程停止、配置移除或 lease 到期后清理内存和连接池。

### 14.2 CredentialLease

```text
CredentialLease
├── lease_id
├── instance_id
├── credential_revision
├── username
├── secret_bytes
├── issued_at
├── expires_at
└── allowed_plugin_identity
```

`secret_bytes` 只存在于 mTLS 响应和进程内存，不进入 JSON 日志、Audit detail 或错误消息。Audit 只记录 lease ID 哈希、instance ID、credential revision、Agent 和结果。

Credential Lease 使用 AgentControl stream 的非持久化请求/响应消息：

- `CredentialLeaseRequest{instance_id, configuration_revision, request_nonce}`
- `CredentialLeaseResponse{request_nonce, lease_id, expires_at, credential}`

Server 只在已验证 Agent、assignment、instance scope 和 configuration revision 全部匹配时返回。该响应不进入 Job/Outbox/ResultAck；通用 gRPC 日志器不得记录 message body。

### 14.3 轮换

- Server credential revision 变化后提升 plugin configuration revision。
- Agent 获取新 lease 并调用 ApplyConfiguration。
- 插件建立新连接池并验证成功后关闭旧池。
- 新凭据失败时保留旧连接直到旧 lease 到期，并上报 rotation_failed。

## 15. 指标模板体系

### 15.1 两层模板

1. **内置模板**：随插件发布、版本化、不可原地修改。
2. **自定义模板**：Server 管理，绑定数据库 family/variant、插件版本范围和发布范围。

内置模板只能通过插件升级改变。管理员可复制为新的自定义模板，但不能覆盖内置 ID。

### 15.2 MetricTemplateRevision

```text
MetricTemplateRevision
├── template_id
├── revision
├── database_family / variants
├── name / description
├── query_kind
├── read_only_statement 或 structured_query
├── collection_interval
├── timeout
├── max_rows / max_columns
├── value_mappings
├── label_mappings
├── metric_types / units
├── database_version_range
├── plugin_version_range
├── cardinality_limits
├── created_by / approved_by
├── query_digest
└── status
```

状态：

```text
draft → validating → validated → trial_running → trial_passed
      → approval_pending → approved → published → superseded
      ↘ validation_failed
      ↘ trial_failed
      ↘ rejected
```

### 15.3 安全限制

SQL 数据库模板：

- 使用数据库方言 AST 校验，不以正则作为唯一安全控制。
- 只允许单条只读 SELECT 或只读 WITH 查询。
- 禁止 DDL、DML、DCL、事务控制、存储过程调用、文件读写和服务端程序执行。
- 禁止多语句和动态 SQL。
- 默认 timeout 5 秒，硬上限 30 秒。
- 默认 max rows 1，硬上限 100。
- 最大列数 32。
- 每个 sample 最大 labels 16，标签值最大 128 字节。
- collection interval 最短 10 秒，最长 24 小时。
- 不允许将任意字符串列作为 metric value。
- 高基数候选必须在试运行中拒绝。

MongoDB、Neo4j、HBase 等后续插件使用各自结构化模板，不伪装成 SQL。

### 15.4 试运行

- 试运行选择一个已纳管实例和一个插件版本。
- Server 创建有界 Job，插件执行一次模板。
- 结果只返回映射后的候选指标、行列计数、耗时和固定诊断。
- 不返回原始业务行。
- 试运行 SQL、结果样本和驱动错误不进入普通 Audit detail。
- 审批人必须与创建人不同，除非项目策略明确允许 self-approval；生产默认禁止 self-approval。

## 16. 第一款 MySQL 插件

### 16.1 支持范围

第一阶段 production evidence 仅覆盖 MySQL 8.x。Manifest 可以声明未来支持 MariaDB、TiDB、OceanBase variant，但 capability matrix 对未验证 variant 返回 `plugin_variant_unverified`。

### 16.2 首批内置指标

| 指标 | 类型 | 来源 |
| --- | --- | --- |
| `mysql.up` | gauge | 连接和轻量 ping 成功为 1，否则为 0 |
| `mysql.connections.current` | gauge | `Threads_connected` |
| `mysql.queries.total` | monotonic counter | `Questions` |
| `mysql.threads.running` | gauge | `Threads_running` |
| `mysql.uptime.seconds` | monotonic gauge | `Uptime` |

模板使用固定 ID，例如 `mysql.core.connections.v1`。插件内部注册 SQL/命令和结果映射；Server policy 选择模板 ID，不能替换内置 statement。

### 16.3 多实例

- 一个进程管理多个实例。
- 每个实例最多一个采集连接和一个连接测试连接。
- 总并发由插件级 semaphore 限制。
- 单实例失败只产生该 instance 的 status sample。
- 第二个实例接入后，插件 PID 和 assignment ID 保持不变，bound instance count 增加。

## 17. Server 模块划分

新增框架无关模块：

```text
backend/internal/
├── hostinventory/
├── discovery/
├── databaseinstance/
├── plugincatalog/
├── pluginassignment/
├── metrictemplate/
├── credentiallease/
└── reconciliation/
```

每个模块包含：

- domain model 和 validation。
- Application Service。
- Repository interface。
- PostgreSQL repository 和 migrations。
- 固定 Problem/error mapping。
- Audit 与 idempotency boundary。

HTTP Handler 只能：

- 读取已验证 principal 和 scope。
- 严格解码 OpenAPI DTO。
- 调用 Application Service。
- 映射固定响应和 Problem JSON。

Domain/Application 层不得依赖 `http.Request`、`http.ResponseWriter`、Chi、Gin 或其他框架 Context。

## 18. OpenAPI 与 API

新增模块：

```text
contracts/openapi/modules/
├── hosts.yaml
├── discovery.yaml
├── database-instances.yaml
├── plugins.yaml
└── metric-templates.yaml
```

主要资源：

- `/hosts`
- `/hosts/{host_id}`
- `/hosts/{host_id}/actions/rediscover`
- `/discovery-candidates`
- `/discovery-candidates/{candidate_id}`
- `/discovery-candidates/{candidate_id}/actions/accept`
- `/discovery-candidates/{candidate_id}/actions/ignore`
- `/database-instances`
- `/database-instances/{instance_id}`
- `/database-instances/{instance_id}/actions/test-connection`
- `/plugin-definitions`
- `/plugin-versions`
- `/plugin-versions/{version_id}/actions/approve`
- `/plugin-assignments`
- `/plugin-assignments/{assignment_id}`
- `/plugin-assignments/{assignment_id}/actions/reconcile`
- `/metric-templates`
- `/metric-templates/{template_id}/revisions`
- `/metric-template-revisions/{revision_id}/actions/validate`
- `/metric-template-revisions/{revision_id}/actions/trial`
- `/metric-template-revisions/{revision_id}/actions/approve`
- `/metric-template-revisions/{revision_id}/actions/publish`

写接口必须使用 Idempotency-Key；条件更新必须使用 If-Match。批量部署和试运行返回 Job，不在 HTTP 请求内长时间执行。

## 19. PostgreSQL 数据模型

第一阶段新增表：

- `managed_hosts`
- `host_observations`
- `discovery_rule_sets`
- `discovery_candidates`
- `database_instances`
- `plugin_definitions`
- `plugin_versions`
- `plugin_assignments`
- `plugin_observations`
- `metric_templates`
- `metric_template_revisions`
- `metric_template_trials`
- `credential_lease_audits`

所有业务表包含 tenant/project scope 或通过不可变父资源约束 scope。查询必须在 SQL 中带 scope，不允许取出后仅在 Go 中过滤。

Plugin assignment 和 instance update 使用 version/ETag CAS。Reconciler claim 使用 PostgreSQL `FOR UPDATE SKIP LOCKED` 和有界 lease，复用现有 Job/Outbox 经验。

数据库中不保存：

- 插件包解压内容。
- 明文数据库密码。
- 试运行原始业务行。
- 完整进程环境变量或命令行。
- 未脱敏 Docker inspect JSON。

## 20. Agent 代码划分

第一阶段新增模块：

```text
backend/internal/agent/
├── hostinventory/
├── discovery/
├── pluginsupervisor/
├── plugingateway/
├── pluginstate/
└── credentialcache/
```

新增程序：

```text
backend/cmd/
├── dbpilot-plugin-mysql/
└── dbpilot-docker-discovery/
```

现有 Agent composition root 只负责装配，不包含具体 MySQL 查询和 Docker Engine DTO。MySQL 驱动只链接到 MySQL 插件；Docker API client 只链接到 Discovery Helper。

## 21. 前端 React 渐进迁移

### 21.1 目录

```text
frontend/
├── app/
│   ├── shell/
│   ├── auth/
│   ├── routing/
│   ├── api/
│   ├── components/
│   └── features/
│       ├── hosts/
│       ├── discovery/
│       ├── instances/
│       ├── plugins/
│       └── metric-templates/
├── generated/
├── modules/       existing legacy modules
└── shared/
```

### 21.2 技术选择

- React。
- TypeScript strict mode。
- Vite。
- React Router。
- TanStack Query。
- 现有 OpenAPI generated client。
- 现有 CSS variables 和 DBPilot 视觉规范。

React shell 的生产登录使用 OIDC Authorization Code + PKCE。Access token 只保存在内存，通过统一 token provider 按请求读取；禁止 localStorage/sessionStorage 保存 token。静态 SPA 通过同源 Nginx `/api/` 访问 Server，401/403 不回退 demo。测试环境的 token 注入只属于验收边界，不能作为生产登录实现。

第一阶段不引入重型 UI 组件库。建立内部最小组件：PageHeader、DataTable、FilterBar、StatusTag、FormField、Drawer、ConfirmDialog、PermissionGate、AsyncBoundary。

### 21.3 迁移策略

1. 建立 React shell、OIDC token provider、租户/项目上下文和权限能力。
2. 新主机/实例/插件/模板页面只用 React。
3. 通过 LegacyModuleHost 保留现有原生模块。
4. 先迁移基础监控和实例巡检，利用现有真实闭环作为回归基线。
5. 后续开发触及旧模块时同步迁移，不冻结所有功能做大爆炸重写。

### 21.4 构建与部署

- Vite 输出静态 bundle，由现有 Nginx 提供。
- 生成 source map 仅用于受控构建 Artifact，不公开发布内部源码路径。
- CSP、静态资源哈希、缓存策略和 query-safe access log 继续作为验收门禁。
- 旧模块不允许自行读取 token/localStorage；继续使用统一 token provider。

## 22. Server 框架策略

第一阶段不更换 Server 框架。

- 保留 Go `net/http`。
- 保留 OpenAPI strict handler。
- 保留 gRPC/Protobuf。
- 拆分 `cmd/controlplane/main.go` 的模块装配函数。
- 统一认证、scope、permission、idempotency、Audit 和 Problem 中间件。
- 新路由不增加 legacy 手写 DTO。

未来若路由嵌套和中间件装配复杂，可引入 Chi 作为薄 Router；所有 Application Service、Domain、Repository 和生成 Handler 保持不变。禁止将业务代码绑定到 Gin/Echo Context。

## 23. React 功能页面

### 23.1 资源管理

- 主机列表。
- 主机详情、Agent 状态、资源趋势、插件状态。
- 待确认数据库候选。
- 实例纳管向导。
- 数据库实例列表和详情。

### 23.2 插件中心

- 插件仓库。
- 插件版本、平台和发布者签名。
- Agent 插件分配和 observed state。
- 部署、停止、灰度、升级和回滚 Job。
- circuit open 和错误历史。

### 23.3 指标模板

- 内置模板目录。
- 自定义模板草稿。
- 静态验证结果。
- 试运行指标预览。
- 审批和发布记录。
- 实例/标签范围和回滚 revision。

页面根据 capability matrix 和项目权限隐藏或禁用操作；浏览器权限只控制显示，Server 始终重新授权。

## 24. 错误模型

固定错误码至少包括：

- `host_not_online`
- `discovery_unavailable`
- `candidate_stale`
- `candidate_duplicate`
- `plugin_artifact_unavailable`
- `plugin_signature_rejected`
- `plugin_manifest_rejected`
- `plugin_platform_mismatch`
- `plugin_protocol_incompatible`
- `plugin_start_failed`
- `plugin_handshake_failed`
- `plugin_circuit_open`
- `plugin_upgrade_rolled_back`
- `credential_lease_failed`
- `instance_unreachable`
- `instance_authentication_failed`
- `instance_tls_failed`
- `database_version_unsupported`
- `template_validation_failed`
- `template_trial_failed`
- `template_high_cardinality`
- `template_not_approved`
- `state_revision_conflict`

驱动原始错误、SQL 文本、endpoint 凭据和文件路径不得直接进入 API Problem、Audit 或插件 observed error。

## 25. 审计与可观测性

必须审计：

- 主机 enrollment/decommission。
- 候选 accept/ignore/merge。
- 实例创建、凭据引用变更、连接测试。
- 插件上传、验证、批准、撤销。
- assignment desired state 变化。
- 部署、启停、升级、回滚和 circuit reset。
- 模板创建、校验、试运行、审批、发布和回滚。
- 凭据 lease 请求的主体、实例、revision 和结果。

Audit 只保存 ID、revision、digest、固定动作和结果，不保存插件包内容、明文凭据、完整 SQL、试运行原始行和 Docker inspect 内容。

平台指标至少包括：

- host online/stale/offline counts。
- discovery candidates by engine/status。
- plugin desired/observed drift count。
- plugin process restart/circuit counts。
- collection success/error/duration by plugin/instance/template。
- credential lease failures。
- reconciler queue/lease/latency。

## 26. 第一阶段实施顺序

1. OpenAPI/Protobuf 契约和 React shell。
2. Host Inventory 与 enrollment API。
3. Native Discovery 和候选持久化。
4. Docker Discovery Helper 和受限协议。
5. Plugin Catalog、Version、Artifact 和签名验证。
6. Plugin Assignment、Server Reconciler 和类型化命令。
7. Agent Plugin Supervisor、A/B slots 和本机协议。
8. Credential Lease。
9. MySQL 插件与五项内置指标。
10. Metric Template workflow。
11. React 主机/候选/实例/插件/模板页面。
12. 完整 Docker/Kylin/MySQL 验收与生产门禁。

实现计划必须按上述依赖拆分，不并行修改同一 OpenAPI、Agent command、Server composition root 或 React shell 文件。

## 27. 测试策略

### 27.1 契约

- OpenAPI lint、breaking、generation、zero drift。
- Agent v1 typed commands protobuf breaking check。
- Plugin v1 protobuf deterministic generation and compatibility。
- 生成 Go/TypeScript client 编译。

### 27.2 Server

- Domain validation unit tests。
- PostgreSQL repository integration tests。
- scope/permission/idempotency/ETag/Audit tests。
- reconciler desired/observed race and lease tests。
- plugin package traversal/symlink/zip bomb/signature tamper tests。
- template workflow and self-approval rejection tests。

### 27.3 Agent

- discovery rule validation and redaction tests。
- native process restart/dedup tests。
- Docker Helper endpoint allowlist tests。
- plugin install path/symlink/hash/signature tests。
- duplicate command and revision fencing tests。
- process crash/restart/circuit tests。
- A/B rollback tests。
- Unix peer credential and launch nonce tests on Linux。
- credential memory/no-disk/no-log tests。

### 27.4 MySQL 插件

- multi-instance isolation tests。
- connection/auth/TLS/version errors。
- five built-in metric mappings。
- counter reset and timestamp handling。
- timeout/max rows/cardinality limits。
- custom SQL AST rejection cases。
- plugin protocol version and configuration revision tests。

### 27.5 React

- permission and scope tests。
- host/candidate/instance workflow tests。
- plugin deployment progress and rollback tests。
- template validation/trial/approval tests。
- token never enters DOM/URL/console/storage tests。
- no configured HTTP failure falls back to demo data。

## 28. 完整验收环境

Compose 验收包含：

- PostgreSQL 16 控制面数据库。
- production control plane。
- Kylin V10 SP1 amd64 Agent。
- `dbpilot-docker-discovery`。
- 两个 MySQL 8 容器。
- Server 托管的签名 MySQL 插件 Artifact。
- 独立 `dbpilot-plugin-mysql` 进程。
- React 前端、Nginx 和 Playwright。

只发布前端动态 loopback 端口。PostgreSQL、MySQL、OIDC、Server、Agent、Helper 和插件均在验收网络内部。

## 29. 完成标准

### 29.1 主机闭环

- Kylin Agent 使用 enrollment 完成主机纳管。
- Server 展示正确 OS/arch/Agent/Heartbeat。
- 前端展示真实 CPU 和内存指标。
- Agent 停止后主机状态按时间窗变为 stale/offline，不伪造零值。

### 29.2 发现闭环

- Kylin 内受控原生数据库进程候选被发现。
- 两个 Docker MySQL 容器被发现为两个候选。
- Docker Helper 不允许任意 Docker 操作。
- 重复扫描不创建重复候选。
- 容器重建的候选按稳定指纹关联或诚实标记 possible_duplicate。
- cmdline/env/password 被脱敏并且不进入 Server 日志。

### 29.3 实例与插件闭环

- 接受第一个候选后，Server 自动创建 assignment 和 Job。
- Agent 下载、验证、安装并启动 MySQL 插件。
- 接受第二个候选后复用相同插件 PID，bound instance count 为 2。
- Server 可停止、启动和重启插件。
- 插件崩溃有界重启，达到阈值后 circuit open。
- 篡改签名、错误哈希、错误平台和协议不兼容包均被拒绝。
- 插件升级失败自动回滚，两个实例恢复采集。

### 29.4 指标闭环

- 两个实例均产生五项 MySQL 指标。
- `mysql.connections.current` 经插件 → Agent → spool → mTLS → Server → PostgreSQL → Monitoring API → React 页面完整展示。
- 主机和 MySQL 指标包含 Server 赋予的正确 tenant/project/host/instance scope。
- 插件停止后数据库指标变为 stale，不补零。
- Agent/Server 重启后重放无重复逻辑样本。

### 29.5 模板闭环

- 自定义模板经过 draft、validate、trial、approve、publish。
- 试运行不返回原始业务行。
- 非只读 SQL、多语句、超时、超行数和高基数被拒绝。
- 未批准 revision 不能下发。
- 回滚后 Agent 和插件收敛到旧 revision。

### 29.6 安全与清理

- 明文凭据、完整 SQL、插件下载签名、私钥和 Docker 原始 inspect 不进入日志、Audit、DOM 或失败 Artifact。
- Agent/插件没有任意 shell command 能力。
- Agent 和插件不持有 Docker Socket。
- 每次验收使用唯一所有权标签，清理只删除精确记录资源。
- 结束后容器、网络、Volume、插件临时目录和测试凭据均为零残留。

### 29.7 平台门禁

- Windows 开发环境 contracts、Node、Go、vet、PostgreSQL、MySQL 和 Compose 门禁通过。
- linux/amd64 静态构建通过。
- 精确 Kylin V10 SP1 amd64 镜像运行 production Agent、Helper 和 MySQL 插件通过。
- CentOS 7+ 与 Kylin V10+ 的 glibc/静态二进制兼容性通过。
- 真实 Kylin VM/bare-metal systemd、Docker Socket 权限和长期运行仍作为生产发布的独立证据。

## 30. 框架迁移成本控制

### 30.1 前端

现在引入 React/TypeScript/Vite，是因为主机、候选、实例、插件、模板审批和实时状态会显著增加表单、轮询、缓存、路由和权限复杂度。新功能直接进入 React，避免继续扩大原生 `app.js` 和重复 adapter。

采用渐进迁移而非重写，确保现有监控和巡检闭环可持续交付。

### 30.2 后端

Go `net/http` 可用于生产。迁移成本取决于业务是否绑定 transport，而不是是否立即使用框架。

本设计强制：

- Handler 不持有业务逻辑。
- Application Service 不依赖 HTTP。
- 中间件使用标准 `http.Handler`。
- 新 DTO 由 OpenAPI 生成。
- Repository 与 Worker 独立于路由。

在此约束下，未来 `net/http` → Chi 只影响路由装配，成本低。若改用 Gin/Echo 并让业务依赖框架 Context，迁移成本会显著上升，因此不采用。

## 31. 风险与缓解

| 风险 | 缓解 |
| --- | --- |
| Docker Helper 持有高权限 Socket | 独立进程、只读 API allowlist、systemd hardening、Agent/插件不持有 Socket、发布前单独威胁建模 |
| 插件协议过早固化 | Plugin v1 保持小接口、open enum、capability negotiation、Buf breaking gate |
| 一个插件多实例导致互相影响 | 每实例连接池/超时/熔断，插件级并发上限，单实例错误不退出进程 |
| 自定义 SQL 压垮生产库 | AST 只读校验、硬超时/行列/频率/基数上限、试运行和人工审批 |
| 插件供应链风险 | Server+Agent 双重签名/哈希验证、无脚本、路径安全、版本撤销、灰度发布 |
| 凭据泄漏 | Secret reference、短期 lease、内存传递、Unix peer 验证、日志/Audit/Artifact 扫描 |
| React 迁移造成旧功能回归 | 新功能先用 React、LegacyModuleHost、监控/巡检优先迁移、双模式测试 |
| Server composition root 继续膨胀 | 模块装配函数、OpenAPI strict handler、Application Service 和 Worker 生命周期分离 |

## 32. 后续阶段

第一阶段稳定后按插件复制能力：

1. PostgreSQL/openGauss 插件。
2. Oracle 插件及 Kylin/授权驱动验证。
3. MariaDB/TiDB/OceanBase variant 真实验证。
4. 达梦插件及专有驱动验证。
5. MongoDB 插件。
6. Neo4j 插件。
7. HBase/HDFS/ZooKeeper 现有 JMX 组件迁入统一插件管理面，但不改变其非 SQL 模型。
8. Kubernetes Discovery Provider。

每个后续插件必须提供独立包、模板目录、能力矩阵、真实数据库验收和生产平台证据，不能仅增加 EngineFamily 枚举即宣称支持。
