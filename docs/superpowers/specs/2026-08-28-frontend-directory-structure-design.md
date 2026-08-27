# DBPilot 前端目录结构优化设计

## 背景

远程更新新增了多组原生前端模块。当前每个模块的 UI、API 与样式文件都放在仓库根目录，入口文件需要逐项维护资源引用，测试也通过根目录相对路径导入模块。继续新增功能会让根目录膨胀，并增加路径维护成本。

## 目标

在不引入构建工具、不改变运行时行为、不破坏现有访问入口的前提下，按功能模块归档前端文件，明确共享资源边界，并让测试与文档路径同步迁移。

## 非目标

- 不引入 React、Vue、Vite 或其他前端构建链。
- 不重写模块内部逻辑、API 协议、CSS 类名或演示数据。
- 不调整 Go 后端目录。
- 不移动根入口 `index.html`，保证现有静态服务器命令和书签继续可用。
- 不修改迁移前已存在且未跟踪的 `docs/design.md`；该文件由后续文档整理单独处理。

## 方案

保留根目录的 `index.html` 作为兼容入口，将前端实现集中到 `frontend/`：

```text
.
├── index.html
├── frontend/
│   ├── app.js
│   ├── shared/
│   │   ├── styles.css
│   │   ├── features.css
│   │   └── enterprise-theme.css
│   ├── modules/
│   │   ├── alerts/       # alert-center.js / alert-api.js / alert-center.css
│   │   ├── monitoring/   # monitoring-center.js / monitoring-api.js / monitoring-center.css
│   │   ├── workorder/    # workorder.js / workorder-api.js / workorder.css
│   │   ├── audit-log/    # audit-log.js / audit-log-api.js / audit-log.css
│   │   ├── reports/      # reports.js / reports-api.js / reports.css
│   │   ├── sql-window/   # sql-window.js / sql-window-api.js / sql-window.css
│   │   ├── sql-review/   # sql-review.js / sql-review-api.js / sql-review.css
│   │   ├── slow-sql/     # slow-sql.js / slow-sql-api.js / slow-sql.css
│   │   ├── locks/        # locks.js / locks-api.js / locks.css
│   │   └── schema-diff/  # schema-diff.js / schema-diff-api.js / schema-diff.css
│   └── tests/            # 与模块目录保持同名的 node:test 用例
├── backend/
└── docs/
```

模块文件名保留现有名称，避免丢失 grep、调试和文档可读性；只改变所在目录。共享 CSS 集中在 `frontend/shared/`，模块 CSS 与对应 UI/API 同目录，保证功能边界内聚。

## 兼容性与引用策略

1. `index.html` 继续位于仓库根目录，只将资源地址改为 `frontend/shared/...`、`frontend/modules/...` 和 `frontend/app.js`。
2. 脚本加载顺序保持不变：各模块 API、各模块 UI，最后加载经典脚本 `frontend/app.js`。
3. 测试迁移到 `frontend/tests/`，仅更新相对导入路径；测试断言和测试运行命令保持不变，`node --test` 仍能自动发现测试。
4. README 和本次新增的设计/计划文档中的路径全部更新为新位置；迁移前已存在的未跟踪 `docs/design.md` 保持不变；`python -m http.server 8080 --directory .` 不变。
5. 不新增根目录兼容副本，避免同一模块出现两份可编辑源码。

## 验证标准

- `node --test` 全部通过，测试数量不少于当前基线 221 个。
- 静态入口 `index.html` 的所有 CSS/JS 引用均指向存在文件。
- `git status` 不出现意外删除或未跟踪的旧模块副本，且 `docs/design.md` 内容保持迁移前不变。
- 通过静态服务器打开 `index.html` 后，Dashboard、告警管理、基础监控和新增八个模块均可加载。

## 风险与回滚

主要风险是路径遗漏，表现为浏览器 404 或测试模块找不到。迁移使用版本控制重命名并分阶段验证；如验证失败，可回滚单次提交恢复原有根目录布局，不涉及后端和运行数据。
