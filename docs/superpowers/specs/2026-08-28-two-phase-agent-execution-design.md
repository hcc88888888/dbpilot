# DBPilot Agent 两阶段执行与并发一致性设计

日期：2026-08-28
状态：已确认

## 1. 背景

DBPilot 当前使用控制面持久化 Job/Outbox、通过 AgentControl 双向流派发类型化命令、由 Agent bbolt journal 去重并执行的模式。任务级测试和 Kylin/PostgreSQL 验证已经覆盖正常路径，但最终跨组件审查确认单阶段协议仍存在无法通过局部条件判断彻底消除的竞态：

- Agent 收到 Command 后立即执行，控制面取消可能与派发穿透。
- 已入 Agent 队列但尚未持久化 ACK 的命令被误认为“未投递”。
- timeout worker 已领取的过期任务可能与后续 heartbeat/result 并发。
- Job 已终结时，矛盾的迟到结果可能被肯定确认但未反映到 Job。
- HTTP 副作用提交后 Audit 失败，幂等记录停留在 processing 且无法修复。

根因是“命令接收”和“允许产生副作用”使用同一个阶段。解决方案是引入 `CommandPrepare → CommandStart` 两阶段协议，并让所有取消、执行、续租和结果操作携带持久化 fencing token。

## 2. 目标

- Start 前的取消保证命令不会执行。
- Start 后的取消以 Agent 真实结果为准，不伪造 cancelled。
- heartbeat、timeout、result 通过 generation/token CAS，旧 worker 不能覆盖新状态。
- Agent 结果收到控制面持久化确认前持续保留并重投。
- Agent/控制面重启后能够从数据库和 journal 恢复协议状态。
- HTTP 写操作的业务副作用、Audit 和幂等响应可以确定性修复。
- 关闭最终审查发现的 Artifact、审计凭据、未知枚举等剩余正确性问题。

## 3. 非目标

- 不在本阶段实现具体 SQL、巡检、备份或自治 executor。
- 不允许任意 Shell 命令。
- 不自动重放已经进入 running 但执行结果不确定的数据库副作用。
- 不修改现有业务页面布局；前端只增加 traceparent 与生成模型兼容处理。
- 不宣称已获得 Kylin arm64 原生运行证据；本阶段继续保留 amd64 V10 SP1 实测和 arm64 静态构建边界。

## 4. 两阶段协议

### 4.1 状态机

```text
pending
  → preparing
  → prepared
  → start_authorized
  → running
  → succeeded | failed | cancelled | timed_out

prepared → cancelled
start_authorized → cancelling → cancelled | succeeded | failed | timed_out
running → cancelling → cancelled | succeeded | failed | timed_out
```

`prepared` 表示 Agent 已将完整签名 envelope 同步写入 bbolt，但没有调用 executor。`start_authorized` 表示控制面在持久化数据库状态中确认未取消并生成 execution token，然后下发 `CommandStart`。只有收到匹配 token 的 Start，Agent 才能进入 running。

### 4.2 消息语义

- `CommandEnvelope` 作为 Prepare 消息，继续包含不可变 `command_id`、`job_id`、Agent ID、类型化命令、投递有效期、nonce 和签名。
- `CommandPrepared` 由 Agent 返回，包含 `command_id`、envelope digest 和 journal state。
- `CommandStart` 由控制面返回，包含 `command_id`、随机 256-bit `execution_token`、`lease_revision`、执行 lease 秒数和开始截止时间。
- `Heartbeat` 中每个活动命令携带 `command_id`、`execution_token`、`lease_revision`。
- `CommandProgress` 与 `CommandResult` 必须携带 `execution_token`、`lease_revision`。
- `CommandCancellation` 携带 command ID、当前 execution token（Start 前为空）和取消原因。
- `CommandResultAcknowledgement` 仅在 Job、Command、Artifact 引用和必要 Audit 已持久化后返回。

所有新增字段在 Agent v1 稳定声明前完成。生成代码必须提交，Buf lint/breaking 和全模块合同测试必须通过。

## 5. 持久化状态与 CAS

`command_outbox` 增加或明确维护以下字段：

- `command_status`
- `prepare_digest`
- `prepared_at`
- `execution_token_hash`
- `lease_revision`
- `execution_deadline_at`
- `execution_last_heartbeat_at`
- `recovery_claim_token`
- `recovery_claimed_deadline`
- `cancellation_requested_at`
- `cancellation_reason`
- `terminal_result_digest`
- `terminal_at`

数据库不保存明文 execution token，只保存 SHA-256 hash。控制面只在 Start 消息构建期间持有原 token；需要重发 Start 时，token 的加密或可恢复表示通过 Credential Reference 管理的控制面密钥封装后持久化。为避免引入新的密钥系统，本阶段采用 AES-GCM 加密列 `execution_token_ciphertext`，密钥由现有 `SecretResolver` 引用 `command.execution_token_key_ref` 获取。

### 5.1 Prepare CAS

派发前执行原子更新：

```text
pending + 未取消 + dispatch claim token 匹配
→ preparing
```

Agent 返回 Prepared 后，控制面使用 `command_id + prepare_digest + 当前状态` CAS 为 `prepared`。Prepare 重试复用完全相同的 envelope 字节。

### 5.2 Start CAS

控制面在一个数据库事务中：

1. 锁定 command 与 Job。
2. 再次检查 Job 未 cancelling/cancelled、target 未终态。
3. 生成 execution token 和递增 lease revision。
4. 持久化 `start_authorized`、token hash/ciphertext 和 deadline。
5. 提交后发送 `CommandStart`。

如果取消事务先提交，Start CAS 必须失败；如果 Start 事务先提交，取消进入 Start 后路径并下发携带 token 的 Cancel。不存在“Cancel 先入 Agent 队列、Prepare 后入队”的顺序歧义。

### 5.3 Timeout fencing

timeout worker 领取过期命令时生成 `recovery_claim_token` 并记录它领取时看到的 `execution_deadline_at` 与 `lease_revision`。最终 timeout 更新必须同时满足：

```text
command_id 匹配
command_status 为 start_authorized/running/cancelling
execution_deadline_at 等于 claimed_deadline
lease_revision 等于 claimed_revision
recovery_claim_token 匹配
```

Heartbeat 续租递增 lease revision 并更新 deadline，因此旧 timeout worker 的 CAS 必然失败。Result terminal CAS 同样携带 execution token hash 和 lease revision。

## 6. 取消语义

### 6.1 Start 前取消

Job cancellation 与 command cancellation intent 在同一 PostgreSQL 事务提交。对于 `pending/preparing/prepared`：

- 状态 CAS 为 cancelled。
- target 写入 cancelled。
- 不发送 CommandStart。
- 如果 Agent 已 prepared，则发送无 execution token 的 Cancel，Agent 删除 prepared journal entry。

### 6.2 Start 后取消

对于 `start_authorized/running`：

- command 状态变为 cancelling。
- 下发包含 execution token 的 Cancel。
- executor 收到 context cancellation。
- 最终状态完全由 Agent Result 决定：成功即 succeeded，失败即 failed，确认取消即 cancelled，超时即 timed_out。

Job 聚合不得仅因 Job 曾处于 cancelling 就强制变成 cancelled。

## 7. Agent journal 与恢复

Journal 持久化完整 Prepare envelope、prepare digest、协议状态、execution token 的 hash/加密值、lease revision、terminal result 和 reported 状态。

- prepared 未 Start：重连后报告 prepared，等待 Start 或 Cancel，不执行。
- start_authorized 但 executor 未启动：校验 token 后启动一次。
- running 后 Agent 进程崩溃：重启不得自动重执行。Agent 报告 `execution_interrupted`，控制面将其按不确定执行处理为 timed_out/failed 并记录 Audit，等待人工检查。
- completed 未 ResultAck：重连后持续重投相同 Result。

ResultAck 必须匹配 command ID、execution token hash、terminal result digest。否定或 retryable Ack 不得标记 journal reported。

## 8. Result 持久化一致性

控制面处理 Result 的顺序：

1. 按 command ID 查找持久化映射并验证 Agent、token、revision。
2. CAS command terminal 状态和 terminal result digest。
3. 幂等更新 Job target/aggregate。
4. `Audit.RecordOnce` 写入 terminal evidence。
5. 提交或确认上述状态全部持久化。
6. 返回成功 ResultAck。

如果 Job 已终态：

- incoming result 与已存 target/result digest 一致：返回成功幂等 Ack。
- incoming result 矛盾：写入 `command.result_conflict` Audit，返回非 retryable 冲突 Ack，绝不把 command 行改成 incoming terminal 状态。

## 9. HTTP 幂等与 Audit 修复

幂等记录增加业务阶段：`processing → side_effect_committed → audited → completed`。

- Job cancel 事务提交后立即保存可重建响应所需的 Job/version 信息。
- Artifact descriptor 生成后先持久化 descriptor 响应。
- Audit 使用稳定 dedupe key 写入。
- completed 最后提交。
- 同 fingerprint 的 processing 重试执行 reconciliation，不再次执行副作用：读取 Job 或已保存 descriptor，补 Audit，再完成幂等响应。

因此 Job 已取消但 Audit 失败不会永久卡在不可修复的 processing。

## 10. Artifact、Audit 与前端兼容

### 10.1 Artifact

- 不收紧 OpenAPI 原有非空字符串 ID。
- 签名 URL 的 path segment 使用 ID 的 base64url 编码，Verify 解码后再校验 HMAC。
- 本地文件访问使用 Go `os.Root` 相对打开，禁止 `..`、绝对路径和 symlink 逃逸，避免 `EvalSymlinks` 与 `Open` 的 TOCTOU。
- Server readiness 前验证 artifact root 可打开、签名 key 可解析且长度满足要求。
- Capability 仅在 Artifact store 与 signer readiness 成功时启用。

### 10.2 Audit

敏感材料规则增加：

- `private_key`、`privatekey`、`dsn`、`connection_uri` 等 key。
- 通用 `-----BEGIN ... PRIVATE KEY-----` PEM。
- MongoDB、MongoDB+SRV、Neo4j、Redis、PostgreSQL、MySQL 等 credential URI。
- Oracle Easy Connect `user/password@//host/service` 与等价形式。

### 10.3 未知枚举

生成脚本对 TypeScript enum 的 `FromJSONTyped` 进行确定性后处理：已知值原样返回，未知值返回 `UnknownDefaultOpenApi`。生成漂移和 Node 测试必须覆盖未来枚举值。

## 11. 权限隔离

OIDC `dbpilot_grants` 仅授权生成的 action-gated platform API，不填充 legacy Projects。现有 alert/monitoring legacy route 只接受：

- 平台管理员；或
- local/certificate inventory 明确配置的 legacy Projects。

平台只读 grant 不能调用任何 legacy mutation。

## 12. 测试与验收

必须包含：

- Prepare 与 Cancel、Start 的并发顺序测试。
- Start CAS 与取消事务竞争的真实 PostgreSQL 测试。
- Heartbeat、timeout claim、Result 三方并发 fencing 测试。
- Agent restart：prepared 不执行、running 不重执行、completed 重投 Result。
- 控制面 crash：Result 未 Ack 时 Agent 重投。
- contradictory late Result 返回冲突 Ack 且不改 Job/command terminal 状态。
- HTTP processing reconciliation 补 Audit/完成响应。
- Artifact 特殊 ID、symlink swap、readiness 失败测试。
- Audit 私钥/DSN/Oracle/MongoDB 凭据测试。
- 未知枚举降级测试。
- 全量合同 lint/breaking/drift、Node、Go、Prism、PostgreSQL E2E、Linux 构建和 Kylin V10 SP1 amd64 smoke。

验收要求：取消后无未授权 Start、旧 timeout claim 无法覆盖续租/结果、ResultAck 只确认已持久化的同一结果、平台 grant 不放大 legacy 权限、所有 verifier 容器与临时文件清理完成。
