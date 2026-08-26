# HBase 依赖拓扑观测设计

## 目标

将 HBase 的运行观测从单一数据库实例扩展为包含 HBase、HDFS、ZooKeeper 的依赖组件观测组。三类组件保持独立采集、独立版本适配和独立凭据边界，但在 DBPilot 中通过拓扑关系统一展示指标、健康状态、告警和根因线索。

本设计只覆盖观测能力：指标采集、标准化、依赖关联、健康评分和告警上下文。表管理、HDFS 文件操作、ZooKeeper 管理命令不属于本阶段范围。

## 组件与采集入口

### HBase

通过 HBase Master 和 RegionServer 暴露的 JMX HTTP/JSON `/jmx` 端点采集。每个端点支持 HTTP/HTTPS、超时、重试、认证和 TLS Secret 引用。采集 Bean 与属性采用白名单，禁止执行 JMX 写操作。

覆盖 JVM、Master、RegionServer、Region、Store、BlockCache、MemStore、WAL、Flush、Compaction、Split 和请求延迟等指标。

### HDFS

通过 NameNode 和 DataNode JMX HTTP/JSON `/jmx` 端点采集，支持 HTTPS、认证、TLS Secret、超时和重试。覆盖 NameNode 容量、文件/Block 数、Under-replicated Blocks、安全模式、RPC 延迟，及 DataNode 存活、磁盘使用、I/O、BlockPool、坏盘和数据块损坏等指标。

### ZooKeeper

优先使用 ZooKeeper 暴露的 JMX 端点；对于未启用 JMX 的部署，允许配置只读管理指标入口作为兼容方案。采集入口、认证、TLS、超时和重试均由配置驱动。覆盖 Leader/Follower 状态、Quorum 成员、请求延迟、Outstanding Requests、连接/会话数、ZNode、Watch、事务日志和快照状态。禁止执行管理变更命令。

## 统一数据模型

新增非 SQL 组件指标适配器模型。适配器负责连接、读取和解析；公共管道负责采样时间、资源标签、spool 投递、重试和状态上报。

每条指标必须包含：

- `cluster`: 逻辑集群标识
- `component`: `hbase`、`hdfs` 或 `zookeeper`
- `role`: `master`、`regionserver`、`namenode`、`datanode`、`leader`、`follower` 等
- `host` 与 `instance`
- `metric_name`、数值、单位和采样时间
- 可选的 `jmx_object_name` 与原始属性名，便于排障

指标名称采用 DBPilot 命名空间，避免直接暴露不同版本 Bean 名称。版本差异通过组件版本映射表处理；无法识别的 Bean 不应被静默映射为其他指标。

## 依赖拓扑

HBase 集群配置增加依赖引用，而不是复制连接信息：

```yaml
hbase:
  hbase_endpoints: [...]
  hdfs_cluster_ref: hdfs-prod
  zookeeper_cluster_ref: zk-prod
```

依赖引用必须解析到已授权的 HDFS/ZooKeeper 集群。拓扑服务维护 `HBase -> HDFS` 和 `HBase -> ZooKeeper` 关系，并保留组件、角色、主机和采集时间维度。

拓扑关联只读取元数据和指标，不允许通过依赖引用绕过组件自身的访问控制。某个依赖不可达时，HBase 指标仍可独立采集，但健康评分和告警上下文必须标记数据不完整。

## 健康评分、告警与根因线索

每个组件先计算自身健康状态，再由拓扑聚合器计算 HBase 观测组状态。聚合结果必须区分“组件故障”和“依赖故障”，避免把 HDFS 或 ZooKeeper 问题误报成 HBase 自身故障。

初始规则示例：

- HBase 写延迟升高且 DataNode 磁盘或 I/O 异常：生成 HDFS 依赖线索
- RegionServer 请求堆积且 ZooKeeper 会话或 Quorum 异常：生成 ZooKeeper 依赖线索
- HDFS 副本不足或 NameNode 容量临界：提示 HBase WAL/Flush 风险
- ZooKeeper 会话数、Outstanding Requests 或事务日志异常：提示 RegionServer 注册和故障转移风险

规则只提供证据链和关联标签，不在本阶段自动执行修复操作。告警去重键应包含集群、组件、角色和规则标识。

## 安全与可靠性

- 所有端点均采用最小权限只读账号。
- 凭据和 TLS 材料仅使用 Secret 引用，运行时解析，不写入指标或日志。
- HTTP/JMX 请求设置连接、读取和整体 deadline；失败按指数退避重试，并上报适配器状态。
- 端点 URL、Bean、属性和管理路径均需通过白名单校验，禁止任意路径、脚本和 JMX 操作。
- 指标解析失败按字段报告，不因单个 Bean 缺失丢弃整批合法指标。
- 采集结果先写 Agent spool，再由 Server 统一处理，支持断网重放和重复投递去重。

## 测试与验证

1. 单元测试：JMX JSON 解析、版本 Bean 映射、单位转换、标签生成、缺失字段和错误脱敏。
2. 合同测试：三个适配器均满足统一指标适配器接口、deadline、Secret 和 TLS 约束。
3. 集成测试：使用可复现的 HBase/HDFS/ZooKeeper 测试环境验证端点连通、依赖引用、指标入 spool 和告警关联。HBase 依赖环境较重，不与 MySQL/PostgreSQL Compose 混用。
4. 运行时验证：在 Docker Linux 环境验证采集器；在 Kylin V10 容器中验证 Agent 二进制启动、配置加载、JMX 采集和 spool 投递。无法启动真实依赖服务时，必须明确标注为解析/合同测试，不能宣称端到端支持。

## 分阶段交付

1. 公共非 SQL 指标适配器接口、组件模型和拓扑引用。
2. HBase JMX 适配器及指标映射。
3. HDFS JMX 适配器及指标映射。
4. ZooKeeper JMX/只读管理指标适配器。
5. 拓扑聚合、健康评分、告警上下文和根因线索。
6. Docker/Kylin 验证、文档和运维配置示例。
