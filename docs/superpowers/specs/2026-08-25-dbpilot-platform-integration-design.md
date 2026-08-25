# DBPilot 统一平台与开源能力复用设计

## 1. 决策摘要

DBPilot 的前端、业务控制面、权限、工单、审计和 Agent 全部自研。成熟产品不作为用户入口，不直接承载 DBPilot 的用户、租户和业务状态；后端模块按“引入开源库、封装独立工具、裁剪或 Fork 核心能力”三个层级复用成熟项目。

该方案适用于企业内部自用平台。所有引入或修改的开源项目仍需保留版权信息、维护组件清单并完成许可证和安全审查。

## 2. 设计目标

- 为 Oracle、MySQL、MariaDB、达梦、OceanBase、HBase、Neo4j、MongoDB、TiDB、PostgreSQL 和 openGauss 提供统一运维入口。
- 保持页面风格、导航、权限、任务状态、错误处理和审计体验一致。
- 缩短 SQL 审核、监控、结构对比、备份和 AI 等能力的研发周期。
- 第三方代码和产品可升级、可替换，不污染 DBPilot 核心领域模型。
- 所有数据库操作均经过 DBPilot 权限、审批、策略和 Agent 执行链。

## 3. 总体架构

```text
DBPilot Web（React + TypeScript）
               │
DBPilot API Gateway / BFF
               │
┌──────────────┼──────────────────────────┐
│              │                          │
IAM / Policy   Workflow / Audit           Module APIs
│              │                          │
│              │              ┌───────────┼────────────┐
│              │              │           │            │
│              │          SQL Review   Monitoring   AI Gateway
│              │          SQL Execute  Inspection   Reporting
│              │              │           │            │
└──────────────┴──────────────┴───────────┴────────────┘
                               │
                    Agent Gateway（gRPC + mTLS）
                               │
                         DBPilot Agent
                               │
                  Database Adapter / Tool Runner
```

前端只调用 DBPilot API。模块服务不得要求浏览器直接访问第三方服务，也不得建立独立用户和权限体系。

## 4. 统一前端

前端使用 React、TypeScript 和统一设计系统。每个业务模块拥有独立页面布局，但共享以下基础组件：

- 应用壳、导航、面包屑和项目切换器。
- 实例选择器、时间范围、筛选器和能力提示。
- SQL 编辑器、结果表格、执行计划、Diff 和风险标签。
- 任务状态、审批时间线、审计信息和错误详情。
- 图表主题、空状态、加载状态、权限拒绝和降级提示。

前端路由权限用于改善体验，后端 Policy Service 是最终授权点。所有页面通过 BFF 获取面向页面组合后的 ViewModel，避免前端分别理解多个模块或第三方接口。

## 5. 统一控制面

DBPilot 是以下数据的唯一事实来源：

- 用户、部门、租户、项目和角色。
- 数据库实例、Agent、连接凭据引用和能力矩阵。
- 工单、审批、任务、任务步骤和执行状态。
- 巡检策略、告警规则、报告模板和自治策略。
- 全局审计事件、Trace ID 和第三方资源映射。

模块服务只能通过稳定 API 访问这些数据，不能直接读写其他模块的表。

## 6. 权限模型

授权范围按以下层级表达：

```text
Tenant → Project → Instance → Database/Schema → Object → Action
```

统一动作包括 `instance.view`、`metric.read`、`sql.query`、`sql.export`、`sql.explain`、`sql.ddl`、`session.kill`、`ticket.approve`、`backup.restore` 和 `audit.read`。

API Gateway 将已验证的用户上下文传给模块服务；模块服务调用 Policy Service 决策。高风险任务由 Control Plane 签发短期执行声明，Agent 再校验目标、动作、审批单、过期时间和签名。

## 7. 开源能力复用规则

### 7.1 引入开源库

适用于 SQLFluff、SQLGlot、数据库驱动、OpenTelemetry SDK 和文档生成库。库被封装在模块内部，DBPilot 对外只暴露自有协议。

### 7.2 封装独立工具

适用于 pgBackRest、WAL-G、XtraBackup、Exporter、VictoriaMetrics 和 Alertmanager。工具独立运行，由模块服务或 Agent 通过受控命令和 API 调用。

### 7.3 裁剪或 Fork

仅在没有稳定 API、核心能力成熟、代码边界独立、许可证允许且维护成本低于自研时采用。Fork 后移除原产品的 UI、用户、租户、工单和权限模块，只保留目标引擎能力。

每个 Fork 必须记录上游仓库、固定版本、许可证、补丁集、升级策略、安全负责人和替换接口。

## 8. 模块实现边界

| 模块 | DBPilot 自研 | 复用或参考 |
|---|---|---|
| SQL 审核 | 编排、规则配置、风险模型、结果协议、元数据关联 | SQLFluff、SQLGlot；参考 Bytebase、Yearning |
| SQL 改写 | Prompt、基线、语义及性能验证 | SQLGlot、LLM、DB-GPT |
| SQL 窗口 | 页面、执行网关、权限、限额、历史 | Monaco Editor；参考 CloudBeaver、DBeaver |
| 巡检 | 策略、调度、问题模型、报告 | PMM Advisor、Percona Toolkit |
| 基础监控 | 统一指标模型、API 和页面 | Exporter、OTel、VictoriaMetrics、Grafana API |
| 慢 SQL | 治理流程、统一 QueryDigest、建议模型 | PMM QAN、pt-query-digest、pgBadger、pg_stat_monitor |
| 锁透视 | 锁事件模型、关系图、事务回放 | 数据库系统视图和日志 |
| 根因诊断 | 证据链、推导流程、建议与工单联动 | Advisor 规则和数据库诊断脚本 |
| 结构对比 | 任务、权限、结果和报告 | Liquibase、DBDiff |
| 备份恢复 | 策略、审批、任务和状态 | pgBackRest、WAL-G、XtraBackup |
| 会话与限流 | 页面、策略和任务编排 | ProxySQL、PgBouncer、数据库原生能力 |
| 参数管理 | 快照、Diff、审批、验证与回滚 | 数据库系统参数、pgtune、MySQLTuner |
| 工单与版本 | 全部业务模型和流程 | 参考 Bytebase、Yearning、Liquibase、Flyway |
| 账号权限 | 权限编排、审批和审计 | 数据库原生 RBAC；参考 Bytebase |
| 报告中心 | 模板、生成、调度、归档、邮件 | 图表渲染和文档生成库 |
| AI 小助手 | 聊天 UI、Tool Gateway、权限和审计 | DB-GPT、LLM |
| 自治管理 | 策略、灰度、效果验证和回滚 | HypoPG、ProxySQL、Agent |

## 9. SQL 审核服务

```text
Review API
├── Dialect Detector
├── Parser Adapter（SQLGlot / SQLFluff / Vendor Parser）
├── Rule Engine
├── Metadata Resolver
├── Risk Evaluator
├── Index Advisor
├── Rewrite Service
└── Verification Service
```

审核结果使用 DBPilot 自有模型：问题码、位置、严重级别、阻断策略、证据、建议、修复 SQL、语义验证和性能估算。任何第三方规则码均在适配层转换。

## 10. 监控和性能数据

DBPilot Agent 是统一安装入口，也是数据库、主机、操作系统日志、自定义文件和自定义指标的统一采集入口。Agent 为 Go 单进程单二进制，不运行独立 Vector；其内部复用 OpenTelemetry Collector Go 组件构建 receiver / processor / exporter 管道，Vector 只作为功能、背压和可靠性设计参考。

日志和指标先进入 DBPilot Ingest Gateway，由 Gateway 根据 Agent mTLS 身份补充并校验租户、项目、主机和实例信息。基础指标写入 VictoriaMetrics；数据库日志、操作系统日志、审计日志和 SQL 样本写入 ClickHouse；原始日志归档写入企业 S3。Grafana 仅用于图表定义和渲染，不承担业务权限。

PMM 不作为统一监控底座。需要 MySQL、PostgreSQL 或 MongoDB 深度 Query Analytics 时，可选择性复用其采集器、指标定义或算法，但数据必须转换为 DBPilot 的 `QueryDigest`、`QuerySample`、`WaitEvent`、`LockEvent` 和 `DiagnosticFinding` 模型。

## 11. Agent 与数据库适配器

DBPilot Agent 负责主机指标、数据库指标、数据库日志、操作系统日志、自定义文件、自定义指标、本地缓存、工具执行和结构化命令。采集内核与命令执行器共享 Agent 身份和控制通道，但在代码、权限和资源配额上隔离。Agent 不接受原始 Vector/OTel 配置，也不允许采集策略提供任意 Shell。

Adapter 按连接、元数据、指标、会话、锁、Explain、审计和操作声明能力。HBase、Neo4j 和 MongoDB 使用各自查询模型，不伪装成传统 SQL 数据库。

## 12. AI 安全边界

DB-GPT 或 LLM 不直接持有生产数据库凭据。AI 只能调用 DBPilot Tool Gateway 暴露的结构化工具。每次工具调用必须执行权限校验、参数校验、数据裁剪、敏感字段处理和审计；DDL、DML、Kill、恢复和参数变更必须创建工单并等待审批。

## 13. 技术栈收敛

- Go：Control Plane、Agent、网关、调度、监控和执行服务；Agent 内嵌 OTel Collector Go 组件。
- Python：SQLFluff、SQLGlot、AI 和诊断算法。
- Java：仅用于必须依赖 JDBC 或 Java SDK 的数据库插件。
- gRPC + Protobuf：内部服务和 Agent 协议。
- PostgreSQL：控制面数据和首期任务 Outbox；VictoriaMetrics：指标；ClickHouse：日志、审计和 SQL 样本；企业 S3：原始日志、报告和任务产物。

第一阶段不默认引入 NATS、Kafka、Elasticsearch 或额外微服务。任务量或事件解耦需求明确后再引入 NATS JetStream；日志量需要独立流式缓冲时再评估 Kafka。

## 14. 统一事件和审计

核心事件包括 `agent.registered`、`instance.discovered`、`sql.review.requested`、`ticket.approved`、`job.dispatched`、`job.completed`、`metric.alerted` 和 `ai.tool.requested`。

每个跨模块流程携带同一 Trace ID。审计事件至少记录用户、项目、实例、动作、工单号、Agent Job ID、输入摘要、审批链、结果和时间。

## 15. 失败与降级

- 开源引擎不可用时，模块返回明确降级状态，不绕过审核或权限继续执行。
- 第三方结果必须经过 Schema 校验，未知字段不得直接进入核心模型。
- Agent 离线时缓存采集数据，不执行高风险离线任务。
- 每个 Fork 和外部工具均需健康检查、版本检查、超时、熔断和替换实现。
- AI 不可用时不影响人工 SQL 审核、工单和执行流程。

## 16. 测试策略

- 核心领域模型和权限规则使用单元测试。
- 模块与开源引擎之间使用契约测试和固定输入输出样本。
- 每个数据库 Adapter 使用容器或专用测试环境做兼容测试；商业数据库使用隔离测试实例。
- Agent 命令执行覆盖签名错误、过期、重放、超时、取消和断网恢复。
- Agent 采集测试覆盖文件轮转、截断、多行、编码、journald 游标、checkpoint、背压、磁盘满、断网恢复、配置原子切换和高基数拦截。
- 发布测试覆盖 Linux amd64/arm64 静态构建，以及 CentOS 7、麒麟 V10 x86_64/arm64 的真实环境冒烟测试。
- SQL 审核使用多方言黄金样本集；开源依赖升级必须重新运行回归集。
- 端到端测试覆盖登录、查询、审核、审批、执行和审计闭环。

## 17. 实施顺序

1. 建立统一领域模型、权限动作、API 规范和 Agent 协议。
2. 完成 MySQL、PostgreSQL、Oracle 的 Agent 与基础监控闭环。
3. 完成 SQL 审核、SQL 窗口、工单和执行闭环。
4. 扩展其余数据库 Adapter、巡检、告警和报告。
5. 建设性能洞察、锁透视、根因诊断和索引推荐。
6. 接入 AI Tool Gateway，最后实施自治能力。

## 18. 验收原则

- 用户始终停留在 DBPilot 前端。
- 权限、工单、任务和审计均以 DBPilot 数据为准。
- 替换任一开源引擎不需要修改前端或核心领域模型。
- 所有高风险操作均可追溯、可取消、可验证并具备明确回滚策略。
- 每个支持的数据库均通过能力矩阵准确展示可用功能。
