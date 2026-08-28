# DBPilot 实例巡检与报告闭环设计

> 状态：聊天设计已确认，待书面复核

## 1. 目标

在 DBPilot 现有 Agent、遥测、Job、AgentControl、Artifact、Audit、RBAC 和报告前端基础上，实现可投入内部试用的实例巡检闭环：

- 支持立即巡检和定时巡检。
- 支持单实例与批量实例。
- 主机层巡检优先覆盖所有部署 Agent 的目标。
- 数据库层优先覆盖支持 SQL 的关系型数据库。
- 支持系统巡检项与受控的自定义巡检项。
- 生成不可变的巡检报告快照，并接入报告中心。
- 单个目标失败不阻断同批其他目标，结果能够明确表达部分完成。

本阶段遵循功能优先原则。会导致错误判断、错误执行、数据错误或核心流程失败的问题必须立即修复；不影响当前功能正确性的安全加固、异常恢复增强、性能优化和代码质量问题登记后集中处理。

## 2. 范围与分阶段覆盖

### 2.1 第一阶段

主机层面覆盖全部 Agent 目标，包含：

- CPU 使用率、负载和调度压力。
- 内存、Swap 和 OOM 证据。
- 文件系统空间、inode、只读挂载和增长风险。
- 网络连通、连接错误和接口异常。
- 时间同步状态。
- 数据库关键进程与端口状态。
- 操作系统错误日志与数据库关键错误日志摘要。
- Agent 在线、采集新鲜度、spool 和策略状态。

数据库层优先覆盖 Oracle、MySQL、MariaDB、达梦、OceanBase、TiDB、PostgreSQL 和 openGauss。第一批数据库巡检包括：

- 连通性、版本、角色和运行状态。
- 连接或会话压力。
- 锁、长事务和阻塞摘要。
- 容量、表空间或数据库空间使用。
- 复制或集群角色状态（适用时）。
- 关键参数和配置漂移。
- 适配器已注册的只读健康探针。

MySQL 与 PostgreSQL提供真实 Docker 集成验证。MariaDB、OceanBase、TiDB、openGauss 复用各自兼容族的模板但保持独立 capability；Oracle 和达梦使用各自方言模板。没有真实测试环境的数据库只声明“契约已实现”，不能声明“生产验证通过”。

HBase、MongoDB 和 Neo4j 第一阶段只参加主机、进程、端口、日志和采集状态巡检。其数据库专属深度巡检后续补齐；不支持的巡检项返回 `unsupported`，不得伪造健康状态。

### 2.2 第一阶段不包含

- 任意 Shell、任意 SQL 或用户上传脚本执行。
- HBase、MongoDB、Neo4j 数据库专属深度巡检。
- PDF/Word 报告生成和邮件发送。
- 基于性能洞察的异常现场回放。
- 自动执行修复建议。

上述能力进入后续功能批次，不阻塞第一阶段交付。

## 3. 架构

采用“Server 统一编排和判定，Agent 执行受控采集与只读探针”的混合模式。

```text
Web UI
  -> Inspection HTTP API
    -> Policy / Scheduler / Run Service
      -> Job + Command Outbox
        -> AgentControl Prepare -> Start
          -> CollectNow / InspectionProbe
            -> Host collectors / Database adapters
      -> Result evaluator
        -> Findings + immutable report snapshot
          -> Artifact + Report Center
      -> Audit
```

职责边界：

- `inspection` 领域是巡检策略、巡检项、运行、目标结果、问题和报告快照的事实来源。
- Job/Command 负责批量执行、进度、取消、超时和 Agent 交付，不复制巡检领域状态机。
- Agent 只执行签名命令中声明的受支持能力，不接收规则表达式、原始 SQL 或 Shell。
- 数据库适配器持有只读探针模板及结果解析逻辑。
- Server 根据版本化巡检项和结构化观测值计算严重级别。
- Artifact 保存报告产物；报告中心引用巡检报告快照，不重新计算历史结论。

## 4. 领域模型

### 4.1 InspectionItem

巡检项至少包含：

- `id`、`version`、名称、描述和分类。
- `scope_type`：`host` 或 `database`。
- `source_type`：`metric`、`metadata`、`log_summary` 或 `probe`。
- 数据库类型与 capability 限制。
- 结构化判定条件、警告阈值、严重阈值和证据选择器。
- 建议模板和文档引用。
- 系统项/自定义项标记、启用状态和变更审计字段。

自定义指标项使用受限结构，而不是可执行表达式文本：指标名、标签过滤、时间窗口、聚合函数、比较运算符、警告阈值和严重阈值。自定义探针项只能引用管理员预先注册的探针模板 ID。

### 4.2 InspectionPolicy

策略包含：

- 租户、项目、名称、启用状态和版本。
- 立即或 cron 类定时配置、时区和下次执行时间。
- 显式目标或标签选择器。
- 巡检项 ID 与固定版本。
- 每目标超时、批次并发上限和创建/修改审计字段。

策略更新使用 `If-Match` 版本控制。一次运行必须保存策略快照和巡检项版本，后续修改不能改变历史报告。

### 4.3 InspectionRun 与 TargetRun

运行状态：

```text
queued -> collecting -> evaluating -> generating_report
       -> completed | partial | failed | cancelled
```

目标状态：

```text
pending -> collecting -> evaluating
        -> succeeded | failed | unsupported | cancelled
```

`partial` 表示至少一个目标产生有效结果且至少一个目标失败、不支持或缺少数据。所有目标均无法产生有效结果时为 `failed`。

运行保存 Job ID、触发来源、策略快照、计划发生时间、开始/结束时间、目标计数和报告 ID。目标运行保存实例、Agent、Command、进度、错误代码与数据新鲜度。

### 4.4 InspectionFinding

Finding 等级固定为：

- `healthy`
- `warning`
- `critical`
- `unsupported`
- `missing_data`

Finding 保存巡检项版本、目标、观察时间、结构化证据、判定阈值、问题摘要和建议。`unsupported` 与 `missing_data` 不参与健康数量，必须独立展示。

### 4.5 InspectionReport

报告快照包含运行与策略摘要、目标结果、Finding、证据、建议、Job/Command/Audit 关联和生成时间。快照写入后不可修改；重新巡检生成新报告。

第一阶段输出 HTML 与 JSON Artifact。报告中心列出、查看和下载这些 Artifact。

## 5. Agent 与数据库适配器

### 5.1 主机采集

立即巡检先通过现有 `CollectNow` 要求 Agent 刷新受支持的主机、日志和进程数据。Server 只在新鲜度窗口内使用数据；超时或过旧数据产生 `missing_data`。

定时巡检复用相同流程，不直接读取任意主机文件或执行系统命令。

### 5.2 InspectionProbe 强类型命令

Agent Protobuf 增加 `InspectionProbe` 命令与对应结构化结果，包含：

- command、run、target 和 instance 引用。
- 数据库类型。
- 预注册 `probe_template_id` 与模板版本。
- 参数白名单值，不包含 SQL 文本。
- 截止时间和现有两阶段执行 fence。

Agent 根据数据库类型和模板 ID 查找适配器探针。未注册组合返回 `unsupported`；连接或查询失败返回稳定错误代码。命令继续遵守 Prepare/Start、取消、结果持久化和 ResultAck 语义。

探针必须只读、设置超时和结果行/字节上限，且使用 Credential Reference 获取账号。凭据、连接串和原始敏感结果不得进入日志、spool、Finding 或报告。

## 6. 编排、调度与幂等

- `POST /inspection-runs` 使用 Idempotency-Key；同一请求不得创建重复 Job。
- Scheduler 以策略 ID、策略版本和计划发生时间构造唯一 occurrence key。
- 多控制面实例通过 PostgreSQL `FOR UPDATE SKIP LOCKED` 和有界租约抢占到期策略。
- 创建 Run、TargetRun、Job 和 outbox 必须在一致的事务边界内完成，避免孤立运行。
- 每个目标独立执行；一个目标失败不取消其余目标。
- 取消 Run 复用 Job 取消语义，尚未 Start 的目标不得执行探针。
- 控制面内部的投递、采集、评价和报告修复重试复用相同 Run/Target/Command 身份，不能重复产生 Finding 或报告。用户对已终态 Run 发起“重新执行”是一个新的业务操作：创建新的 Run/Job/Command 身份并保存 `retry_of_run_id`，同一个重新执行请求仍受 Idempotency-Key 去重。

计划调度失败记录可重试状态；调度器重启后从持久化 `next_run_at` 恢复。第一阶段不支持错过多次后无限补跑，只补最近一次未完成 occurrence。

## 7. 判定与报告生成

Evaluator 输入仅包含版本化巡检项、结构化观测值和采样时间。判定规则是确定性的，同一输入必须得到同一 Finding。

数据处理顺序：

1. 验证目标 scope、数据类型、模板版本和时间范围。
2. 判断 capability 与数据新鲜度。
3. 运行聚合和阈值判定。
4. 生成 Finding 与结构化证据。
5. 聚合目标和批次状态。
6. 预留稳定的报告与 Artifact ID，并把 Run 转入 `generating_report`。
7. 生成 HTML/JSON Artifact；成功后在一个数据库事务中固化不可变报告快照、Artifact 引用和 Run 终态，并以稳定 dedupe key 写入 Audit。

Artifact 生成失败时 Run 保持 `generating_report` 可修复状态，不重复执行主机采集或数据库探针。

## 8. HTTP API 与权限

首批 `/api/v1/tenants/{tenantId}/projects/{projectId}` 接口：

- `GET /inspection-overview`
- `GET /inspection-targets`
- `GET /inspection-items`
- `POST /inspection-items`
- `GET /inspection-policies`
- `POST /inspection-policies`
- `GET /inspection-policies/{policyId}`
- `PATCH /inspection-policies/{policyId}`
- `POST /inspection-policies/{policyId}/run`
- `GET /inspection-runs`
- `POST /inspection-runs`
- `GET /inspection-runs/{runId}`
- `POST /inspection-runs/{runId}/cancel`
- `POST /inspection-runs/{runId}/retry`
- `GET /inspection-reports`
- `GET /inspection-reports/{reportId}`
- `POST /inspection-reports/{reportId}/download`

权限分为 `inspection:view`、`inspection:manage` 和 `inspection:execute`。所有读写都使用 URL scope 和 OIDC principal，不能信任请求体中的租户、项目或 actor。

列表使用稳定 cursor 分页。写操作使用幂等键；策略更新使用 ETag/If-Match。错误返回现有 Problem Details 结构和稳定错误码。

## 9. 前端

前端保持现有无框架模块约定和企业后台视觉，新增：

- 巡检概览：覆盖率、等级统计、趋势、最近失败和数据来源标识。
- 巡检策略：立即/定时配置、目标选择、巡检项选择和启停。
- 巡检任务：状态、进度、目标列表、取消和失败重试。
- 巡检报告：摘要、目标导航、Finding 证据、建议和下载。

页面使用生成客户端与共享 control-plane boundary。没有 Server 地址时可保留显式标记的演示数据；配置真实 Server 后，401/403/5xx 不得回退演示数据。巡检模块完成验收时，真实控制面模式不得依赖演示数据。

报告中心增加巡检报告类型和详情跳转，不复制巡检计算逻辑。

## 10. 错误与部分成功语义

- Agent 离线：目标 `failed`，错误码 `agent_offline`。
- 数据超出新鲜度：对应巡检项 `missing_data`。
- 数据库类型或模板不支持：对应巡检项 `unsupported`。
- 探针超时：目标可继续评价已有数据，最终 Run 通常为 `partial`。
- 单个规则定义非法：该项失败并记录配置问题，不影响其他项。
- Artifact 生成失败：保留可修复报告状态，不重复现场操作。
- 用户取消：未开始目标取消；已经 Start 的探针按 Agent 真实 Result 收口。

不得把未知、缺失、不支持或执行失败映射为 `healthy`。

## 11. 存储

PostgreSQL 新增：

- `inspection_items`
- `inspection_policies`
- `inspection_policy_items`
- `inspection_runs`
- `inspection_target_runs`
- `inspection_findings`
- `inspection_reports`

大体积报告正文放入 Artifact 存储；数据库保存不可变快照摘要、Artifact ID 和查询所需字段。结构化证据有明确大小上限。

租户和项目字段存在于所有领域表及唯一键中。运行、目标、Finding 和报告不提供更新历史结论的通用接口。

## 12. 验证与验收

### 12.1 自动测试

- 规则判定表驱动单元测试。
- 自定义巡检项结构和边界测试。
- 策略版本、ETag、幂等和 occurrence 去重测试。
- Run/Target 状态机及部分成功测试。
- Scheduler 多实例抢占、租约过期和重启恢复测试。
- Agent `InspectionProbe` 验证、Prepare/Start、取消与重投测试。
- 每个 SQL 数据库适配器的模板契约和结果解析测试。
- PostgreSQL 迁移、scope 隔离与事务回滚集成测试。
- MySQL 8 与 PostgreSQL 16 Docker 真实只读探针测试。
- 前端 API、状态渲染、权限和无演示回退测试。

### 12.2 平台验证

- Windows 执行完整 Node、Go、契约生成和 PostgreSQL 集成验证。
- Docker Desktop 执行 MySQL/PostgreSQL 适配器验证。
- Kylin V10 SP1 amd64 容器执行 Agent、主机采集、强类型巡检命令和报告链路 smoke。
- CentOS 7+、Kylin V10+ 构建边界保持不变。

### 12.3 完成标准

- 能对多台主机和 SQL 数据库实例执行立即巡检。
- 定时策略不会为同一 occurrence 重复创建任务。
- 目标失败不会阻塞其他目标，最终状态正确表达部分完成。
- 数据缺失、不支持和健康状态严格区分。
- 报告可追溯策略、巡检项、Job、Command、Artifact 和 Audit。
- 巡检真实控制面模式不依赖演示数据。
- 所有新增测试和现有回归测试通过。

## 13. 后续事项

以下项目登记为后续功能，不阻塞第一阶段：

- HBase/HDFS/ZooKeeper、MongoDB、Neo4j 专属深度巡检。
- Oracle、达梦、MariaDB、OceanBase、TiDB、openGauss 的真实环境验证证据。
- PDF/Word、邮件发送和自定义报告模板。
- 性能洞察现场回放和自动根因关联。
- 自动修复与自治联动。
- 不影响功能正确性的安全、恢复、性能和代码质量增强。
