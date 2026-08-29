# DBPilot 数据库运维管理系统

DBPilot 是一套面向企业生产环境的数据库运维管理平台，覆盖**监控告警、SQL 质量、变更审批、数据安全、容量治理**等运维场景。系统以 Go 后端（遥测采集 Agent + 控制面）与原生 Web 前端（无框架）构成，目标平台为 CentOS 7+ / Kylin V10，安全模型基于 mTLS 与签名策略。

> 仓库来源：https://github.com/hcc88888888/dbpilot.git（main 分支）

---

## 功能模块

### 已实现（前端，10 个模块）

| 模块 | 导航入口 | 说明 |
| --- | --- | --- |
| 概览 Dashboard | 运维中心 / Dashboard 大盘 | 实例运行状况、资源趋势、告警与任务总览 |
| 基础监控 | 监控与报告 / 基础监控 | 主机/进程/数据库指标、实例健康状态、趋势查询 |
| 告警管理 | 监控与报告 / 告警管理 | 告警事件、规则、通知策略、模板、静默管理 |
| 工单管理 | SQL 质量与变更 / 工单管理 | DDL/DML 变更审批、执行与回滚闭环 |
| SQL 窗口与执行 | SQL 质量与变更 / SQL 窗口与执行 | 在线查询、执行计划、查询历史、CSV 导出 |
| SQL 审核 | SQL 质量与变更 / SQL 审核 | 规则引擎审核、风险等级、评分、规则管理 |
| 慢 SQL 治理 | 运行保障 / 慢 SQL 治理 | 慢 SQL 排行统计、趋势、索引建议 |
| 锁透视 | 运行保障 / 锁透视 | 锁等待、死锁、长事务、未提交事务分析 |
| 结构对比 | 数据安全 / 结构对比 | 跨实例对象结构对比与差异 DDL 同步 |
| 审计日志 | 数据安全 / 审计日志 | 操作审计、筛选检索、详情还原 |

> 其余模块（SQL 智能改写、版本列表、实例巡检、性能洞察、根因诊断、会话与限流、索引推荐、存储分析、参数调优、自治管理、账号权限、AI 小助手）为占位页，待后续开发。

### 后端（Go，仓库既有）

- `dbpilot-agent`：嵌入式遥测采集进程（文件日志 / journald / 主机指标 / Prometheus / SQL 指标），本地 spool 缓存 + mTLS gRPC 导出
- 控制面（control plane）：认证、指标摄入、监控查询、告警控制面
- 数据库适配器：MySQL、PostgreSQL、Oracle、达梦(DM)、HBase、HDFS、ZooKeeper（含依赖拓扑观测）
- 告警引擎：规则评估、通知（Webhook/SMTP）、审计；PostgreSQL 存储（6 个迁移）
- 策略体系：签名策略信封 + 版本管理

---

## 技术栈

- **后端**：Go 1.27、gRPC/Protobuf、PostgreSQL、bbolt、Docker Compose
- **前端**：原生 HTML / CSS / JavaScript（ES Module，无框架、无构建工具）
- **测试**：Go `go test`；前端 Node.js 内置 `node --test`（node:test + assert/strict）

---

## 目录结构

```
.
├── index.html                  # 前端入口（导航 + 模块挂载）
├── frontend/
│   ├── app.js                  # 导航注册与模块路由
│   ├── shared/                 # 公共样式
│   ├── modules/<feature>/      # 功能模块（UI / API / CSS）
│   └── tests/                  # 前端测试（node:test）
├── backend/                    # Go 后端（agent / controlplane / adapters）
│   ├── cmd/                    # 程序入口
│   ├── internal/               # 内部实现（agent/alert/database/telemetry/...）
│   └── docs/                   # 后端运维文档
└── docs/                       # 前端与架构设计文档（specs / plans）
```

---

## 本地运行

前端为纯静态页面，任意静态服务器均可：

```bash
python -m http.server 8080 --directory .
# 浏览器打开 http://localhost:8080/index.html
```

无后端配置时模块自动使用内置演示数据（界面标注「演示数据」）；配置控制面地址后走真实 API：

```js
window.DBPILOT_CONTROL_PLANE_URL = 'https://control-plane.example.com';
window.DBPILOT_ALERT_CONTEXT = { authenticated: true, tenantId: 'xxx', projectId: 'yyy', permissions: { manage: true } };
```

后端构建与部署参见 `backend/README.md`。

---

## 测试

```bash
npm ci
npm run contracts:lint
npm run contracts:breaking
npm run contracts:verify
node --test
cd backend && go test ./...
```

标准 `node --test` 会跳过一个 opt-in Prism 集成用例。显式验证 mock server 时运行
`npm run contracts:mock:test`；脚本会启动固定版本 Prism、执行用例并清理容器。

### 合同开发与完整门禁

OpenAPI 与 Agent Protobuf 的唯一可编辑源分别位于 `contracts/openapi/` 与
`contracts/protobuf/`。修改后运行 `npm run contracts:generate`，并提交
`backend/gen/`、`frontend/generated/` 的生成结果；不得直接手改生成文件。
`contracts:breaking` 以 `origin/main` 为基线阻止破坏性 Agent v1 变更，
`contracts:verify` 会重新生成并拒绝 drift。

开发期间可用 `npm run contracts:mock:start` 启动 Prism，结束后运行对应的
Docker Compose `down`；自动化路径优先使用会自行清理的
`npm run contracts:mock:test`。主机巡检的策略、证据新鲜度、partial、不可变报告、
修复与保留语义见 `docs/host-inspection-operations.md`。以下门禁覆盖真实 PostgreSQL
双目标巡检、Job→Command 两阶段 E2E、Linux 交叉构建及批准的 Kylin 生产 Agent：

```powershell
powershell -NoProfile -File backend/scripts/verify-host-inspection.ps1
powershell -NoProfile -File backend/scripts/verify-contract-foundation.ps1
powershell -NoProfile -File backend/scripts/verify-kylin-docker.ps1 `
  -Image 'cr.kylinos.cn/kylin/kylin-server-platform:v10sp1' -Architecture amd64
```

主机巡检 PostgreSQL 脚本只发布动态分配的 loopback 端口，并在 `finally` 中按记录的
容器 ID/所有权标签清除自身容器与匿名卷。Kylin 门禁必须使用上述精确镜像与 amd64，
运行生产 Agent/native host reader，解码真实 spool 中非空 CPU、内存、文件系统、负载和
snapshot timestamp，并验证 ResultAck 已写入 journal；静态数据、通用 Linux 或
`-SkipKylin` 不构成完成证据。GitHub CI 运行公开 PostgreSQL 门禁，不依赖私有 Kylin registry。

完整的浏览器、OIDC、Agent mTLS、重启补发、非法身份、PostgreSQL 与 journal
Compose 验收由 `backend/scripts/verify-full-stack-compose.ps1` 统一编排。它只接受精确
Kylin V10 SP1 镜像，按唯一所有权标签记录并清理资源；成功不保留产物，失败只保留脱敏
诊断。先阅读 [全栈 Compose 验收说明](docs/full-stack-compose-acceptance.md)。普通 CI 只运行
Compose 静态解析和 fake-Docker 清理契约；真实私有镜像门禁必须显式手动启用。

Agent 命令采用 `Prepare → Start` 两阶段执行。Prepare 只把签名 envelope 同步写入
Agent journal，不调用 executor；只有控制面在 PostgreSQL 中原子提交 Start fence 后，
匹配 execution token/revision 的 Start 才能产生副作用。取消事务若先提交，则不生成
Start 且清除 prepared journal；Start 若先提交，则发送带 fence 的取消，最终状态以 Agent
真实 Result 为准。heartbeat 与 timeout claim 使用 recovery revision CAS，旧 timeout worker
不能覆盖续租或终态结果。

Agent 会保留 terminal Result，直到控制面持久化 Job、Command、Artifact 引用及 Audit 后
返回匹配 digest 的 `ResultAck`；控制面在 Ack 前崩溃时，Agent 重连会重投。Agent 在
running 状态崩溃后不会自动重执行，重启证据记为 timed_out 并要求人工核对真实数据库
副作用。HTTP 写操作在业务副作用已提交而 Audit 失败时，使用持久化响应和稳定 dedupe key
补写 Audit，不重复执行取消/签名。Artifact capability 只在存储根可安全打开且签名密钥满足
readiness 要求后启用。

当前 `/api/v1` 允许一次 pre-stable 迁移。工单、SQL 窗口、SQL 审核、慢 SQL、
审计日志、锁透视、结构对比与报告这八个模块全部切换到生成客户端和 strict
server handler 后，v1 进入 additive-only 稳定边界。

---

## Change History 变更历史

> 约定：每次功能开发或修复完成后，在本节顶部追加一条变更记录（倒序），格式见各条目。

### 2026-08-28 · v0.2.0 第二批前端模块

- **新增模块**：SQL 审核（sql-review）、慢 SQL 治理（slow-sql）、锁透视（locks）、结构对比（schema-diff）
- **新增文件**：
  - `frontend/modules/sql-review/sql-review.js` / `frontend/modules/sql-review/sql-review-api.js` / `frontend/modules/sql-review/sql-review.css` + `frontend/tests/sql-review.test.js`
  - `frontend/modules/slow-sql/slow-sql.js` / `frontend/modules/slow-sql/slow-sql-api.js` / `frontend/modules/slow-sql/slow-sql.css` + `frontend/tests/slow-sql.test.js`
  - `frontend/modules/locks/locks.js` / `frontend/modules/locks/locks-api.js` / `frontend/modules/locks/locks.css` + `frontend/tests/locks.test.js`
  - `frontend/modules/schema-diff/schema-diff.js` / `frontend/modules/schema-diff/schema-diff-api.js` / `frontend/modules/schema-diff/schema-diff.css` + `frontend/tests/schema-diff.test.js`
- **变更内容**：
  - SQL 审核：内置演示规则引擎（SELECT *、缺 LIMIT、无 WHERE 高危变更、模糊查询、破坏性语句、凭据检测等 7 类规则），输出风险等级/评分/命中详情，支持批准驳回与规则启停
  - 慢 SQL 治理：Top 排行、执行统计、趋势图（CSS bar）、排序与阈值筛选、索引建议（含优化 DDL）、标记已处理/忽略
  - 锁透视：锁等待/死锁/长事务/未提交事务四类事件；「阻塞者 vs 等待者」双列对比、锁对象与锁模式中文映射、死锁回放
  - 结构对比：新建对比（源→目标实例 + 对象类型多选）、差异摘要四色计数、对象差异明细、差异 DDL 生成与同步
- **集成**：`index.html` 引入 8 组 CSS/JS；`frontend/app.js` 注册 sql-review / slow-sql / locks / schema-diff 路由
- **验证**：全量 221 个用例通过（含此前 144 个，无回归）

### 2026-08-28 · v0.1.0 第一批前端模块

- **新增模块**：工单管理（workorder）、审计日志（audit-log）、报告中心（reports）、SQL 窗口与执行（sql-window）
- **新增文件**：
  - `frontend/modules/workorder/workorder.js` / `frontend/modules/workorder/workorder-api.js` / `frontend/modules/workorder/workorder.css` + `frontend/tests/workorder.test.js`
  - `frontend/modules/audit-log/audit-log.js` / `frontend/modules/audit-log/audit-log-api.js` / `frontend/modules/audit-log/audit-log.css` + `frontend/tests/audit-log.test.js`
  - `frontend/modules/reports/reports.js` / `frontend/modules/reports/reports-api.js` / `frontend/modules/reports/reports.css` + `frontend/tests/reports.test.js`
  - `frontend/modules/sql-window/sql-window.js` / `frontend/modules/sql-window/sql-window-api.js` / `frontend/modules/sql-window/sql-window.css` + `frontend/tests/sql-window.test.js`
- **变更内容**：
  - 工单管理：DDL/DML/DCL 变更创建、审批流、执行日志时间线、回滚，状态机 pending→approved→executing→executed/rolled_back
  - 审计日志：15 种操作类型、多维筛选（操作/结果/实例/用户/时间范围）、详情还原与失败原因警示
  - 报告中心：报告生成（模拟状态流转）、模板管理、邮件分发（邮箱校验）、下载
  - SQL 窗口：SQL 编辑器（Ctrl+Enter 执行）、按语句类型模拟执行、EXPLAIN 计划树、查询历史、CSV 导出（转义 + UTF-8 BOM）
- **集成**：`index.html` 引入 4 组 CSS/JS；`frontend/app.js` 注册 tickets / audit / reports / sql-window 路由
- **验证**：全量 144 个用例通过

### 2026-08-28 · v0.0.1 项目初始化

- 从 GitHub 克隆 `dbpilot` 仓库到工作区（main 分支，HEAD `282ff4e`，120 个既有提交）
- 梳理项目现状：Go 后端（约 3.1 万行，不含生成的 pb.go）+ 原生前端（概览 / 基础监控 / 告警管理已实现）
- 建立前端模块开发约定：API 层（demo/unavailable/http 三适配器 + 敏感信息脱敏 + 统一错误对象）+ UI 层（create 工厂 + 纯函数 + XSS 转义 + forbidden 固定文案 + scope 变更 abort）+ 独立样式 + node:test 测试
