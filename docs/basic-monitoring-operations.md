# DBPilot 基础监控运行手册

## 边界与数据流

基础监控只展示已认证 Agent 上报、由控制面分配到租户/项目后的安全指标视图：

```text
Agent metric envelope → mTLS ingest → metric_samples + monitoring_instances
                                  → scoped Control Plane API → 基础监控工作台
```

Agent 身份映射是唯一的租户/项目来源；metric envelope 不得包含或覆盖
`tenant_id`、`project_id`、`agent_id` 或 `scope`。页面只调用控制面 API，
不直接连接 Agent、数据库、VictoriaMetrics 或任意指标后端。更换 PostgreSQL
查询实现或未来的 VictoriaMetrics 实现时，必须保持 `QueryStore` 和下列 API
DTO 兼容，前端不应随存储实现变化。

## API 与授权

所有请求必须经过既有的控制面身份和作用域中间件。路径中的租户/项目与已认证
主体不匹配时返回固定的 `403 forbidden`；同一作用域找不到实例时返回
`404 not_found`。不接受客户端在请求体、标签或查询参数中提供作用域声明。

| 路径 | 用途 | 有界参数 |
| --- | --- | --- |
| `GET /api/v1/tenants/{tenantID}/projects/{projectID}/monitoring/overview` | 健康摘要、实例目录和范围趋势 | `from`、`to`、`step` |
| `GET .../monitoring/instances` | 实例列表 | `engine`、`status`、`limit`、`offset` |
| `GET .../monitoring/instances/{id}` | 一个实例及其指标序列 | `from`、`to`、`step` |
| `GET .../monitoring/series` | 一个实例的一条指标序列 | `instance_id`、`metric`、`from`、`to`、`step` |
| `GET .../monitoring/capabilities` | MySQL、PostgreSQL、Oracle 指标能力目录 | 无 |

响应总是由服务端写入 `source: "control-plane"` 和已验证的 `scope`。前端仅将
HTTP `401`、`403`、`404`、`413` 与服务不可用映射为固定的中文提示；不会显示数据库
错误，也不会因 HTTP 失败切换成演示数据。`permissions.manage` 只控制“自定义指标”
入口是否可见，不替代服务端读取授权。

## 查询和数据语义

- 默认查询窗口为最近 1 小时；最大窗口为 7 天。`from < to`，时间按 RFC3339 UTC
  规范化。
- 默认步长为 1 分钟；客户端工作台默认选择 5 分钟。请求步长必须为正，完整范围最多
  1,000 个桶。
- 实例列表单页 `limit` 为 1–200；未知数据库类型或状态筛选会被拒绝。
- 每个桶都显式返回。没有样本的桶为 JSON `null`，页面渲染为 `—` 和缺口，绝不能把
  它显示或聚合为 `0`。
- Agent 心跳超过两个采集周期未更新为“离线”；心跳仍在但最后样本超过两个采集周期为
  “数据陈旧”；其余为“健康”。历史范围中没有样本不会删除已知实例目录。

服务端读取和完整 HTTP 响应都受以下限额约束。零值采用默认值；配置值不能超过硬上限，
超限统一返回 `413 query_limit_exceeded`，而非部分截断数据。

| 项目 | 默认 | 硬上限 |
| --- | ---: | ---: |
| 实例 | 200 | 1,000 |
| 指标名 | 50 | 200 |
| 每个实例标签 | 32 | 64 |
| 样本 | 10,000 | 50,000 |
| 完整 JSON 响应 | 1 MiB | 4 MiB |

控制面配置可按部署需要收紧这些值：

```yaml
monitoring:
  maximum_instances: 200
  maximum_metrics: 50
  maximum_labels: 32
  maximum_samples: 10000
  maximum_response_bytes: 1048576
```

## 页面行为与来源标记

`#monitoring`（侧边栏“基础监控”）打开独立监控工作台，不走通用功能卡片，也不改变
`#alerts-config` 或其他功能路由。页面包含“监控概览”、“实例列表”与选中实例的
“实例详情”。切换租户/项目、时间范围、筛选或步长时会取消旧请求、清空当前选择和序列，
再加载新作用域的数据，避免旧范围数据覆盖新视图。

`演示数据` 仅在未配置控制面基地址的显式 demo adapter 中出现，并在界面上作为来源标记。
`控制面服务` 表示数据来自受控 HTTP API。demo adapter 与 HTTP adapter 独立：HTTP 的
拒绝、网络或服务错误始终显示固定错误和“重试”按钮，绝不回退到 demo 数据。

## 规范指标名与 capabilities

指标名是区分大小写的稳定标识，不是 UI 文案；同一逻辑指标不得同时以点号和下划线两种
名字上报。基础监控的跨引擎展示约定如下。它们用于展示、筛选、告警规则和受控模板引用；
`unit` 由上报样本或能力定义提供，页面不从指标名字推断敏感连接信息。

| 规范 ID | 含义 | 常用单位 | 适用范围 |
| --- | --- | --- | --- |
| `host.cpu` | 主机 CPU 使用率 | `%` | 任意受管实例 |
| `host.memory` | 主机内存使用率 | `%` 或 bytes（以样本 unit 为准） | 任意受管实例 |
| `db.connections` | 当前数据库连接数 | `count` | MySQL、PostgreSQL 及受控模板 |
| `db.qps` | 数据库每秒查询数 | `requests/s` | MySQL 受控模板 |
| `db.transactions` | 数据库事务数或速率 | `count` 或 `transactions/s` | PostgreSQL 受控模板 |
| `db.sessions` | 数据库会话数 | `count` | Oracle 及受控模板 |
| `db.wait_time` | 数据库等待时间 | `ms` | Oracle 受控模板 |

上述通用 ID 是基础工作台和 demo 的规范展示词汇，不是绕过 Adapter 的任意 SQL 接口。生产
`GET .../monitoring/capabilities` 才是某个控制面部署可读取指标的权威目录：只展示
`metrics: true` 的引擎和其 `metric_ids`，并由后端的受控 Adapter/模板注册填充。调用方
不得将文档中的一个 ID 视为对所有部署均可查询的承诺。

当前内置 SQL capabilities 的解释如下：

| 引擎 | `metrics` | `metric_ids` 语义 |
| --- | --- | --- |
| MySQL | `true` | 内置协议 Adapter 支持指标采集；具体 SQL 模板目录由部署注册，因此空列表不表示可执行任意 SQL。 |
| PostgreSQL | `true` | 同 MySQL；`transactions` capability 另表示受控事务能力，不是客户端授权。 |
| Oracle | `true` | 固定只读模板：`oracle.sessions`、`oracle.transactions`、`oracle.locks`、`oracle.tablespace`、`oracle.slow_sql`。 |

新增指标必须先在受控 Agent policy 或 Adapter/模板目录中注册，携带 canonical resource labels
`instance`、`component`、`role`、`host`，再由 capabilities API 公布。不要以 UI 输入、
PromQL、原始 SQL 或临时标签创建新指标名；这样既会破坏跨范围聚合，也会绕过安全审计边界。

## 存储、保留与安全

生产查询使用 PostgreSQL 中由认证摄取维护的 `metric_samples` 与
`monitoring_instances`。后者保留最后样本与接收时心跳，因而可在当前展示范围没有样本时
仍正确分类已知实例。迁移会从既有样本回填实例；回填记录的心跳等于历史样本时间，不能
被解释为新鲜 Agent 心跳。

`metric_samples` 按日分区。保留期是运维策略，而非控制面后台任务：创建未来至少七天的
分区，并按合规批准的指标保留期删除过期日分区，避免对父表做大型行删除。完整迁移、备份
和保留操作说明见 [告警控制面运行手册](../backend/docs/alert-control-plane-operations.md)。

原始 Agent payload、数据库错误、SQL、连接串、DSN、密码、token、credential 与其他
secret 字段不得进入 monitoring DTO、页面、审计摘要或日志。摄取阶段拒绝敏感标签；查询
和浏览器 adapter 会再次剔除不安全字段。排障时只使用已脱敏的错误码、时间范围、实例 ID
和请求关联信息。

## 故障排查

1. `403`：核对客户端证书/主体的项目授权与 URL 中的 tenant/project；不要尝试用前端
   权限开关绕过授权。
2. `404`：核对实例是否由属于该项目的已认证 Agent 上报，并检查 `monitoring_instances`
   中的作用域记录。
3. `413 query_limit_exceeded`：缩短时间范围、增大步长，或按容量计划在硬上限内调整
   `monitoring` 配置；不要使用无界查询。
4. “数据陈旧”或“离线”：检查 Agent mTLS 连通性、采集周期、控制面摄取错误与最后
   `last_sample_at` / `last_heartbeat_at`。历史查询仍可用不代表采集健康。
5. 页面显示“无法查看此项目”或“服务暂时不可用”：保留固定 UI 错误信息并检查控制面
   日志和就绪状态；页面不会暴露服务端错误详情。

## Linux 与 Kylin V10 验证边界

Windows 上的 Go/Node/静态浏览器验收证明 API 契约、工作台路由和渲染行为，不构成 Linux
Agent 或 Kylin 运行时兼容性结论。发布前应在 CentOS 7 amd64、Kylin V10 amd64 与 Kylin
V10 arm64 的受控运行器上，使用真实 mTLS 网关完成 Agent 启动、认证摄取、控制面查询和
基础监控页面读取的记录；保留每个平台的 Agent 与控制面日志。

Windows Docker 的 Kylin 检查仅可使用批准的 Kylin V10 镜像，并按
[backend README](../backend/README.md) 的 `verify-kylin-docker.ps1` 流程执行。它验证
二进制兼容性和 bootstrap 启动，不覆盖 systemd、journald ACL、内核指标、eBPF 或真实服务
生命周期；这些仍需要 Kylin VM 或裸机证据。验证不应删除或检查 telemetry spool 中的
未确认数据。

在任一 Linux/Kylin 运行器完成应用级验收时，先运行控制面与 Agent 的完整 Go 测试，再由
受控 Web 服务器加载静态页面，选择“基础监控”，核对概览、列表、详情、`null` 缺口、
陈旧/离线文字、来源标记、时间切换和 `403` 重试态。窄屏验收使用 390px 宽度；记录截图和
命令输出，但不要把 secret、原始 payload 或凭据纳入测试证据。
