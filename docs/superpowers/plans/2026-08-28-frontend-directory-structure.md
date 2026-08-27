# DBPilot 前端目录结构优化实施计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task with verification checkpoints.

**Goal:** 在不改变原生前端运行时行为的前提下，将模块源码、共享资源和测试按功能边界归档到 `frontend/`，并保持根入口与现有启动命令兼容。

**Architecture:** 根目录保留 `index.html` 作为静态入口；`frontend/app.js` 负责导航和模块注册；`frontend/shared/` 保存公共样式；`frontend/modules/<feature>/` 保存同一功能的 UI、API 和 CSS；`frontend/tests/` 保存前端 node:test 用例。迁移只改变路径和引用，不改变业务逻辑与浏览器全局接口。

**Tech Stack:** 原生 HTML、CSS、JavaScript ES Module、Node.js `node:test`、Git。

**Spec:** `docs/superpowers/specs/2026-08-28-frontend-directory-structure-design.md`

## Global Constraints

- 不引入 React、Vue、Vite 或其他构建工具。
- 根入口必须继续是 `index.html`，静态服务器命令保持 `python -m http.server 8080 --directory .`。
- 模块文件名保持现有名称；只改变所在目录。
- 不修改模块业务逻辑、API 协议、CSS 类名、演示数据或后端目录。
- 保留现有未跟踪的 `README.local.backup.md`、`.tooling/`、`docs/design.md` 和 `backend/internal/telemetry/dbpilot-spool/`，不改写这些文件内容。

---

### Task 1: 创建前端目录并迁移源码

**Files:**
- Create: `frontend/shared/`, `frontend/modules/<feature>/`, `frontend/tests/`
- Move: 根目录 `app.js` 到 `frontend/app.js`
- Move: `styles.css`、`features.css`、`enterprise-theme.css` 到 `frontend/shared/`
- Move: 每个模块的 JS/API/CSS 到对应 `frontend/modules/<feature>/`
- Move: 根目录 `tests/*.test.js` 到 `frontend/tests/`

**Interfaces:**
- Produces the same files and exports at new paths; no function signatures change.

- [x] **Step 1: Verify all source targets and destinations are explicit**

  Run:

  ```powershell
  $modules = @('alerts','monitoring','workorder','audit-log','reports','sql-window','sql-review','slow-sql','locks','schema-diff')
  $modules | ForEach-Object { New-Item -ItemType Directory -Force -Path "frontend/modules/$_" | Out-Null }
  New-Item -ItemType Directory -Force -Path frontend/shared,frontend/tests | Out-Null
  ```

- [x] **Step 2: Move shared files and module files with Git-aware renames**

  Run:

  ```powershell
  git mv app.js frontend/app.js
  git mv styles.css features.css enterprise-theme.css frontend/shared/
  git mv alert-center.js alert-api.js alert-center.css frontend/modules/alerts/
  git mv monitoring-center.js monitoring-api.js monitoring-center.css frontend/modules/monitoring/
  git mv workorder.js workorder-api.js workorder.css frontend/modules/workorder/
  git mv audit-log.js audit-log-api.js audit-log.css frontend/modules/audit-log/
  git mv reports.js reports-api.js reports.css frontend/modules/reports/
  git mv sql-window.js sql-window-api.js sql-window.css frontend/modules/sql-window/
  git mv sql-review.js sql-review-api.js sql-review.css frontend/modules/sql-review/
  git mv slow-sql.js slow-sql-api.js slow-sql.css frontend/modules/slow-sql/
  git mv locks.js locks-api.js locks.css frontend/modules/locks/
  git mv schema-diff.js schema-diff-api.js schema-diff.css frontend/modules/schema-diff/
  git mv tests/*.test.js frontend/tests/
  ```

- [x] **Step 3: Confirm no old module copies remain**

  Run:

  ```powershell
  rg --files -g '*.js' -g '*.css' | Sort-Object
  git status --short
  ```

  Expected: module implementation files exist only below `frontend/`; unrelated local files remain untouched.

### Task 2: Update the static entrypoint and test imports

**Files:**
- Modify: `index.html:10-21,73-93`
- Modify: `frontend/tests/*.test.js` import and `readFile(new URL(...))` paths

**Interfaces:**
- Consumes: files moved in Task 1.
- Produces: an entrypoint that loads the same resources in the same order and tests that import the new module paths.

- [x] **Step 1: Rewrite CSS and script paths in `index.html`**

  Replace each root stylesheet reference with `frontend/shared/...` for shared files and `frontend/modules/<feature>/...` for module files. Replace the final `app.js` script with `frontend/app.js`; keep all `type="module"` attributes and ordering unchanged.

- [x] **Step 2: Update test-relative imports and repository-level URLs**

  In every file under `frontend/tests/`, change imports from `../<module>.js` and `../<module>-api.js` to `../modules/<feature>/<module>.js` and `../modules/<feature>/<module>-api.js`. Keep `new URL('../app.js', import.meta.url)` for the test that resolves `frontend/app.js`; change the entrypoint assertion from `new URL('../index.html', import.meta.url)` to `new URL('../../index.html', import.meta.url)` because the compatibility entry remains at the repository root. Change the integration-doc assertion from `new URL('../docs/alert-center-integration.md', import.meta.url)` to `new URL('../../docs/alert-center-integration.md', import.meta.url)`.

- [x] **Step 3: Run the complete frontend test suite**

  Run:

  ```powershell
  node --test
  ```

  Expected: 221 or more tests pass, 0 fail, 0 cancelled.

### Task 3: Update documentation and path checks

**Files:**
- Modify: `README.md` directory tree, module file references, and history entries
- Do not modify: pre-existing untracked `docs/design.md`, `docs/alert-center-integration.md`, or other unrelated local documents

**Interfaces:**
- Consumes: new paths from Tasks 1–2.
- Produces: documentation that points to the actual source locations and preserves the existing server command.

- [x] **Step 1: Find every stale root-level frontend path**

  Run:

  ```powershell
  rg -n "(^|[`'\" ])(app|styles|features|enterprise-theme|alert-center|alert-api|monitoring-center|monitoring-api|workorder|audit-log|reports|sql-window|sql-review|slow-sql|locks|schema-diff)(-api)?\.(js|css)|tests/" README.md index.html frontend docs/superpowers/specs/2026-08-28-frontend-directory-structure-design.md docs/superpowers/plans/2026-08-28-frontend-directory-structure.md
  ```

- [x] **Step 2: Update documentation to the module-first layout**

  Use `frontend/app.js`, `frontend/shared/<file>`, `frontend/modules/<feature>/<file>`, and `frontend/tests/<file>` in README examples and directory trees. Keep the server command rooted at `.` and keep the root `index.html` URL. Leave the pre-existing untracked documents untouched.

- [x] **Step 3: Verify all documented paths exist**

  Run:

  ```powershell
  $paths = @('index.html','frontend/app.js','frontend/shared/styles.css','frontend/modules/alerts/alert-center.js','frontend/modules/monitoring/monitoring-center.js','frontend/tests/alert-center.test.js')
  $paths | ForEach-Object { if (-not (Test-Path -LiteralPath $_)) { throw "Missing path: $_" } }
  Write-Output 'documented-path-smoke=PASS'
  ```

### Task 4: Browser-style smoke verification and final review

**Files:**
- Test: `index.html` resource references and `frontend/` tree

**Interfaces:**
- Consumes: completed migration and documentation updates.
- Produces: evidence that the static entrypoint can resolve every local CSS/JS resource without 404s.

- [x] **Step 1: Validate every local HTML asset reference**

  Run:

  ```powershell
  $html = Get-Content -Raw index.html
  $refs = [regex]::Matches($html, '(?:href|src)="([^"]+)"') | ForEach-Object { $_.Groups[1].Value } | Where-Object { $_ -notmatch '^(https?:|#|mailto:)' }
  foreach ($ref in $refs) { if (-not (Test-Path -LiteralPath $ref)) { throw "Missing asset: $ref" } }
  Write-Output "asset-refs=$($refs.Count)"
  ```

- [x] **Step 2: Run the complete frontend test suite again**

  Run `node --test` and confirm the same or higher test count with zero failures.

- [x] **Step 3: Review the final diff and status**

  Run:

  ```powershell
  git diff --check
  git diff --stat
  git status --short
  ```

  Confirm that only the intended path moves, reference updates, and documentation changes are present; do not stage or modify the pre-existing local files listed in Global Constraints.
