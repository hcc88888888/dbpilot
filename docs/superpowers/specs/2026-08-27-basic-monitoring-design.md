# DBPilot 基础监控闭环设计

## 目标

把现有 Agent 已采集的主机、数据库和自定义指标，变成 DBPilot 内部可查询、可聚合、可授权的基础监控页面。首期覆盖 MySQL、PostgreSQL、Oracle，并保留其他数据库适配器的统一指标扩展点；前端不直接访问 Agent、数据库或 VictoriaMetrics。

## 范围与非目标

首期包含实例注册信息、Agent 在线状态、主机 CPU/内存/磁盘、数据库连接/可用性、时间范围趋势、最新采样、指标来源与采集健康、实例筛选和自定义指标入口。告警事件继续由既有告警控制面负责，慢 SQL、巡检、报告和性能洞察另立子项目。本期不实现 PromQL 编辑器、复杂图表编排、指标写入代理或新的消息队列。

## 端到端架构

```text
DBPilot Agent
  └─ host/database/custom metric envelopes
       ↓ mTLS ingest (identity resolved server-side)
Control Plane metric store/query service
  ├─ tenant/project authorization
  ├─ instance + adapter capability catalog
  ├─ bounded range aggregation and latest sample queries
  └─ collector health / stale-sample classification
       ↓ scoped JSON API
Self-developed 基础监控 page
```

Agent 继续复用当前嵌入式 OpenTelemetry Collector 和数据库 Adapter。控制面负责统一资源身份、校验指标名称/标签、按租户项目落库，并通过查询服务输出前端 DTO。VictoriaMetrics 作为生产指标存储时由同一查询接口替换当前内存/测试存储，前端协议不变。

## 数据模型

统一指标样本至少包含：`tenant_id`、`project_id`、`agent_id`、`instance_id`、`metric_name`、`value`、`sampled_at`、受限标签和 `source`。实例目录包含数据库类型、版本、主机、Agent 最近心跳、Adapter 能力和采集状态。查询层输出：

- `MonitoringOverview`: 当前范围实例总数、健康/告警/离线计数、采集延迟、重点实例和时间趋势摘要。
- `MonitoringInstance`: 实例身份、数据库类型、状态、关键指标最新值、最近采样时间和采集错误摘要。
- `MonitoringSeries`: 指标名称、单位、聚合方式、时间桶和值；缺失桶明确为 `null`，不补造 0。
- `MonitoringCapability`: Adapter 支持的指标族和自定义指标入口状态。

服务端返回的错误、凭据、连接串和原始 Agent payload 不进入前端 DTO。时间统一 RFC3339 UTC，数值查询限制最大时间范围、实例数、指标数和桶数。

## API

所有路由使用既有作用域中间件：

- `GET /api/v1/tenants/{tenantID}/projects/{projectID}/monitoring/overview?from=&to=`
- `GET /api/v1/tenants/{tenantID}/projects/{projectID}/monitoring/instances?status=&engine=&limit=&offset=`
- `GET /api/v1/tenants/{tenantID}/projects/{projectID}/monitoring/instances/{instanceID}?from=&to=`
- `GET /api/v1/tenants/{tenantID}/projects/{projectID}/monitoring/series?instance_id=&metric=&from=&to=&step=`
- `GET /api/v1/tenants/{tenantID}/projects/{projectID}/monitoring/capabilities`

查询参数只影响当前已认证租户/项目；`instance_id` 必须属于该作用域。接口返回 `source`（例如 `control-plane` 或 `demo`）和安全的 `next_offset`。时间范围默认最近 1 小时，最大 7 天；非法范围返回稳定的 400，不返回数据库错误。

## 前端交互

“基础监控”使用独立工作台而不是通用功能卡片：顶部范围/时间选择，健康摘要卡，实例表格，指标趋势面板和右侧实例详情抽屉。状态同时使用文字和颜色；loading、empty、error、unauthorized、stale sample 分别呈现。切换租户/项目或时间范围时取消旧请求、清空选中实例和图表，重新加载概览与列表。没有管理权限仍可只读查看；自定义指标入口只显示权限允许的能力。

页面不渲染原始日志、SQL、连接串、Secret、Agent 原始 payload 或服务端错误。演示模式显示“演示数据”并且不在 HTTP 错误时回退到演示数据。

## 安全与可靠性

- 采集身份由 mTLS Agent 身份解析，禁止指标 payload 自带租户/项目覆盖。
- 查询服务执行租户/项目/实例三层授权，并限制时间范围、标签基数、聚合桶和响应大小。
- 采样超过两个采集周期未更新标记为“数据陈旧”，不伪装为健康。
- Agent 离线不阻塞已落库历史查询；当前状态显示离线和最后采样时间。
- 所有查询和自定义指标变更记录审计摘要；不记录凭据或原始 payload。
- 内存/测试存储与 VictoriaMetrics 查询实现共享同一接口，替换存储无需改前端。

## 测试与验收

1. Go 单元测试覆盖指标范围校验、聚合/缺失桶、实例作用域、陈旧状态和能力合并。
2. Control Plane HTTP 契约测试覆盖五类接口、401/403/404/400、分页和跨项目实例拒绝。
3. Agent/ingest 集成测试验证 MySQL、PostgreSQL、Oracle 样本经身份解析进入查询存储。
4. 前端 Node 测试覆盖 DTO 映射、时间范围校验、错误状态和安全字段剔除；浏览器验证覆盖概览、列表、详情、时间切换、空态、权限态和 390px 布局。
5. 验收条件：同一 API 可切换内存测试存储与生产指标存储；范围切换不串数据；缺失/陈旧数据明确显示；任何 Secret、连接串或原始 payload 不可见；查询超限返回稳定错误并可重试。

## 后续扩展

新增数据库 Adapter 只需注册能力与指标映射；新增指标无需改变前端协议。慢 SQL、性能洞察、存储分析和参数调优通过后续专用 API 复用实例目录、统一指标查询与权限模型。
