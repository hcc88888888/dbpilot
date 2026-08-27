# DBPilot 告警控制面最终修复报告

## 范围与结论

- 修复基线：`7fbc54d`（最终审查所针对的实现提交）。
- 实现提交：`d91ab7d65c04c8d08a49ec8703f38be1d98dab4a`（`fix(alerts): harden control plane integrity`）。
- 修复范围：最终审查 C1、I1–I9、M1–M3；没有删除测试、放宽 secret/scope/audit 要求或改变既有 OTLP JSON 边界披露。
- 结果：C1、I1–I9、M1–M3 均已实现并有回归证据；全包、vet、显式 PostgreSQL 16 套件、Docker/Kylin verifier 与 diff-check 均通过。
- 提交策略：实现与本报告均只提交到本地 `feature/alert-control-plane`，未 push。本报告提交哈希在提交后通过任务消息交付；报告正文不编码自身不稳定的自指哈希。

## Finding 逐项修复

### C1 — 规则删除、孤儿事件与 readiness

改动：

- `DeleteRule` 在 scoped 事务内锁定规则并在存在任何历史事件时返回 `ErrConfigurationInUse`，因此正常 API 不再制造孤儿事件。
- forward migration 为 `alert_events(tenant_id, project_id, rule_id)` 增加 scoped FK `NOT VALID`：不阻断未知历史库升级，但立即约束所有新写入。
- dispatcher 对升级前已经存在的 orphan event 写入确定性的 `delivery.abandoned` / `orphan_rule` audit，作为可审计终态，不再让每轮 dispatch 永久击穿 readiness。
- server 把任一 scope 的 `summary.FailedRules > 0` 纳入 readiness 失败条件。

回归证据：`TestPostgresRulePolicyReferencesAndDeletionRemainRecoverable`、`TestDispatcherTreatsLegacyOrphanEventAsAuditedTerminalOutcome`、`TestReadinessFailsClosedWhenRuleFailureReturnsNoTopLevelError`。

### I1 — secret-at-rest 与敏感 metric labels

改动：

- policy、delivery 与生产 resolver 统一只接受精确 `env://[A-Za-z_][A-Za-z0-9_]*` 语法；in-app 明确要求空 secret ref。
- 在 API/repository SQL 之前拒绝 raw credential、敏感 matcher/label key 及明显 secret value；metric ingest 与 metric store 两层均执行相同边界。
- delivery 持久化再次验证 channel/secret、目标、正文、subject 和 labels；silence 的外部通道抑制记录只保存合法 `env://` 引用，不保存 secret value。
- migration 用 `NOT VALID` channel/secret checks 保护新写入并保留未知 legacy 行；已知不合法 legacy policy 被禁用/清理并审计，legacy delivery secret ref 被清理或替换为 opaque 环境引用。

回归证据：`TestNotificationPolicyAcceptsOnlyProductionSecretReferences`、`TestPostgresDeliveryPersistenceRejectsRawSecretMaterialBeforeSQL`、`TestPostgresRejectsRawSecretsBeforeAnyControlPlaneTableWrite`、`TestMetricConsumerRejectsSensitiveLabelsBeforePersistence`、`TestEvaluatorRejectsSensitiveResourceLabelsBeforeEventPersistence`、`TestDispatcherSilenceSuppressesDeliveryButWritesAudit`。

### I2 — canonical resource identity 与 missing-data

改动：

- canonical identity 固定要求 `instance`、`component`、`role`、`host` 非空；ingest 和 metric store 都拒绝不完整样本。
- evaluator 对历史库中不完整样本进行防御性过滤，按规则 missing-data policy 处理，并在安全 evidence 中写入 `missing_dimensions`，不再把不可归属低值伪装成 healthy。
- E2E fixture 改为发送完整 canonical labels。

回归证据：`TestMetricConsumerRejectsEachMissingCanonicalResourceDimension`、`TestEvaluatorTreatsIncompleteStoredResourceIdentityAsMissingData` 及 metric store 每维度负向用例。

### I3 — policy 引用完整性与并发删除

改动：

- rule create/update/enable 在同一事务中校验每个 policy ID 存在于相同 scope，并以 `FOR SHARE` 锁定引用行。
- 删除仍被任一 rule 引用的 policy 返回 `ErrConfigurationInUse`；HTTP 映射为 409。
- 删除与并发 enable/update 通过 PostgreSQL row lock 串行化，删除获胜后更新会重新校验并失败，不能提交悬空引用。
- migration 会禁用并清空已经悬空的 legacy rule 引用，同时留下不可变 migration audit。

回归证据：`TestPostgresRulePolicyReferencesAndDeletionRemainRecoverable`、`TestPostgresConcurrentPolicyDeletionCannotRaceRuleEnable`，覆盖 missing、cross-project、delete-in-use 与真实并发竞争。

### I4 — 多 policy route identity 与 legacy key

改动：

- v2 delivery identity 包含 event、state、channel、policy ID、policy revision 与 template version；相同 channel/template 的两个 policy 各自投递。
- policy 配置 revision 变化会产生新的单次 delivery identity。
- reserve 同时识别精确 legacy v1 key，但只对相同 policy/route tuple 生效；legacy 记录不会吞掉第二个 policy，也不会把 v2 policy revision 误去重。
- migration 增加 legacy route lookup index；保留 0001/0002 已存 idempotency key，不重写历史身份。

回归证据：`TestDispatcherKeepsTwoSameChannelPoliciesAsDistinctRoutes`、`TestDispatcherPolicyRevisionCreatesNewRouteIdentity`、`TestDispatcherHonorsLegacyKeyForSameRouteWithoutSuppressingSecondPolicy`、真实 PostgreSQL routing/revision/legacy replay integration tests。

### I5 — matcher presence 与 namespace

改动：

- route 和 silence 都使用 presence-aware lookup；缺键不再等价于存在且值为空。
- 校验 matcher key、空值与 namespace；silence 仅接受定义的 `fingerprint`、`label.*`、`resource.*` 语义，拒绝拼写错误、敏感键和歧义键。

回归证据：`TestRouteMatcherRequiresPresentLabelEvenForEmptyConfiguredValue`、`TestSilenceMatcherRequiresPresentLabelEvenForEmptyConfiguredValue`、`TestPolicyAndSilenceRejectUnsafeOrAmbiguousMatchers`。

### I6 — 实际 due scheduling 与独立 lookback

改动：

- rule 增加独立 `lookback_window`；未提供时向前兼容地默认等于 `evaluation_every`。
- migration 增加 `last_evaluated_at`、`next_evaluation_at`、lease owner/expiry 及 due index。
- PostgreSQL scheduler 使用 scoped `FOR UPDATE SKIP LOCKED` claim、持久 lease 与 completion；不同副本不会重复执行同一 due rule，进程重启后仍从数据库计划恢复。
- evaluator 只执行 due rules，按各规则 cadence 计算下一次时间，并用独立 lookback 查询指标。

回归证据：`TestEvaluatorHonorsEachRuleEvaluationCadence`、`TestEvaluatorUsesLookbackWindowIndependentOfCadence`、`TestPostgresRuleSchedulingLeasesCadenceAndLookbackAcrossReplicas`。

### I7 — per-scope health、readiness 与系统事件

改动：

- evaluator health 按 scope 保存；全局 health 只做保守聚合，scoped overview 使用 `HealthForScope`，后执行的健康 scope 不会覆盖前一个失败 scope。
- server 在完整 all-scope pass 中聚合 error 和 failed-rule summary，任一失败都 fail closed。
- evaluation failure、no-data、delay、backlog 生成带 canonical system labels 的 AlertEvent，走相同 rule route/notification；状态恢复时生成 resolved transition。queue depth 来自持久 due queue。
- 系统 finding 的 pending→firing 共享时间先规范到 PostgreSQL 微秒精度，避免数据库四舍五入造成纳秒级逆序。

回归证据：`TestEvaluatorHealthAggregatesScopesWithoutLastScopeOverwrite`、`TestEvaluatorCreatesAndRecoversRoutableSystemFailureEvent`、`TestEvaluatorRecoversBacklogFindingEvenWhenNoRuleIsDueNextPass`、`TestAlertOverviewUsesOnlyRequestedScopeEvaluatorHealth`、`TestReadinessFailsClosedWhenRuleFailureReturnsNoTopLevelError`。

### I8 — 超过 500 条事件的 dispatch 与 overview

改动：

- dispatch pass 使用稳定 `ORDER BY id` + `AfterID` cursor 循环，处理 scope 内全部事件；ID cursor 支持合法 legacy ID，而不把它错误限制为新 ID 语法。
- overview 改为 PostgreSQL scoped `GROUP BY state` aggregate，不再从前 500 条列表推算。
- backlog reconciliation 同样使用稳定 cursor；测试仓库实现了与生产一致的 cursor/limit 语义。

回归证据：`TestEvaluateAndDispatchUsesStableCursorForEveryEvent`、`TestPostgresEventCursorAndAggregateCoverMoreThanFiveHundredRows`、`TestAlertOverviewCountsMoreThanOnePageOfEvents`、既有 501 条 rule-event pagination 用例。

### I9 — root-cause 与 append-only disposition

改动：

- 新增 scoped `EventDisposition`：acknowledgement、resolution、root_cause，保存 category、secret-safe reason、actor、occurred_at。
- acknowledgement/resolve API 必须提供有效 category/reason，并与 event transition、audit、disposition 在同一事务写入。
- 新增 disposition list 与 root-cause append API，带 scoped 鉴权与稳定分页。
- migration 创建 disposition 表、索引、FK 和拒绝 UPDATE/DELETE 的触发器；历史不可改写。

回归证据：`TestEventDispositionRequiresSafeAppendOnlyFacts`、`TestPostgresEventDispositionIsAtomicScopedAndAppendOnly`、`TestEventRootCauseCluesAreAppendOnlyScopedAndPaginated` 及 HTTP acknowledgement/resolve 事务回归。

### M1 — production-listener E2E acknowledge

改动：Docker/Kylin lifecycle 在 firing/三通道后通过真实 HTTPS endpoint acknowledge，随后读取 disposition 并断言 actor 为受信任的 `fixture-admin`；再继续 silence 与 recovery。

证据：verifier 输出 `EVIDENCE acknowledgement ... actor=fixture-admin disposition=...`，随后 silence、resolved、cross-project 403 和 cleanup 全部通过。

### M2 — PostgreSQL integration 可复现文档

改动：运维文档明确说明普通 `go test ./...` 会跳过 gated PostgreSQL tests，并给出 PostgreSQL 16 临时实例、两个环境变量、显式测试命令及清理步骤。

证据：本轮按文档同等方式显式执行完整套件并通过。

### M3 — EOF diff

改动：移除计划文件多余 EOF 空行。

证据：提交前 `git diff --cached --check` exit 0；报告提交后再次执行全分支 `git diff --check 2abc296..HEAD`。

## Forward migration 与兼容性

- 新增 `0005_alert_control_plane_integrity.sql`，只做 forward migration，不回滚或重写既有 migration。
- `NOT VALID` FK/check 的选择是为了让 populated legacy 0001/0002 数据库可升级；PostgreSQL 仍会立即约束新插入/更新的行。已知可分类的不安全 legacy 配置会被禁用/清理并写 migration audit。
- legacy template version 与 delivery key 原值保留；应用层双读 legacy/v2 identity，未破坏已经 delivered/retry 的重放语义。
- migration unit test、populated legacy PostgreSQL upgrade、legacy replay、policy/template revision、真实路由与并发测试均通过。

## 测试先行与调试证据

关键回归均在实现前或边界加强时观察到失败，随后转绿：

- policy revision 初始被 route tuple 错误去重：期望 2 个 delivery、实际 1；收紧为“仅精确 legacy key 兼容”后通过。
- 501+ 测试发现内存 repository 未实现新 ID cursor，导致重复首页；测试替身补齐生产分页语义后通过。
- 真实 PostgreSQL 发现 `severities=nil` 被驱动编码为 SQL NULL；统一规范为空数组后并发 policy test 通过。
- 真实 PostgreSQL 发现 pending timestamp 四舍五入可比同轮 firing 晚 200ns；系统 finding 时间规范到微秒后通过。
- 首轮 Docker verifier 在 external-channel silence 阶段失败：suppressed row 遗漏合法 env reference，被严格 at-rest 校验拒绝；先增加负向单测，再仅保留 opaque ref，第二轮 verifier 全通过。

## 新鲜最终验证

工作目录：`backend/`，Go binary 为仓库隔离工具链 `..\..\..\.tooling\go\bin\go.exe`。

1. `go test ./... -count=1`：exit 0；所有 package 通过。
2. `go vet ./...`：exit 0；无输出。
3. 设置 `DBPILOT_ALERT_POSTGRES_INTEGRATION=1` 与临时 PostgreSQL 16 DSN 后执行 `go test ./internal/alert -count=1 -timeout 10m`：exit 0，`ok ... 4.656s`。
4. `powershell -File .\scripts\verify-alert-control-plane.ps1 ... -KylinImage cr.kylinos.cn/kylin/kylin-server-platform:v10sp1`：第二轮 exit 0；输出 mTLS metric accepted、firing、in-app/SMTP/Webhook delivered、Webhook 503 retry、ack disposition/actor、silence suppressed、resolved、cross-project 403、cleanup。
5. `git diff --cached --check`：实现提交前 exit 0；报告提交后再执行全分支 diff-check。
6. 临时 PostgreSQL 容器已显式删除；verifier 输出并再次查询确认其容器、network、volume 均无残留。

## 保留边界与剩余疑虑

- **OTLP 边界保持不变。** 当前 Agent hostmetrics spool 是 OTLP protobuf，告警入口仍是 strict canonical JSON fixture client；本轮 verifier 只证明真实 Kylin Agent 启动/policy-status mTLS 和同一 production listener 上的 JSON metric-to-alert。文档没有声称直接 OTLP hostmetrics replay E2E。
- `NOT VALID` 约束为 legacy 可升级性保留；发布后应对迁移 audit 中被禁用/清理的配置进行人工处置，并在历史数据完成修复后安排 `VALIDATE CONSTRAINT`。
- dispatch 现在对全部事件做正确稳定游标扫描，但仍是周期性全量扫描，不是 transition outbox；事件规模继续增长时应单独演进 outbox/consumer，以降低重复读取成本。
- Docker Kylin 镜像验证不是 Kylin VM/裸机发布批准；PKI、网络、备份恢复、升级/回滚和真实主机运维证据仍按运维文档执行。
- 前端页面与 Prometheus/Alertmanager adapter 仍按已确认计划留给独立后续工作，不属于本修复波。
- 既有未跟踪 `backend/internal/telemetry/dbpilot-spool/` 是进入本轮前已披露内容；本轮未修改、暂存或删除它。
