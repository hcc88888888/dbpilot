# Alert Rule Duration JSON Compatibility Implementation Plan

> **For agentic workers:** Execute this plan inline; the task explicitly prohibits subagent delegation. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Restore typed Go-client decoding of alert-rule HTTP responses while preserving both legacy numeric nanosecond durations and the new exact duration-string format.

**Architecture:** Keep `AlertRule.MarshalJSON` as the browser-safe string encoder. Add `AlertRule.UnmarshalJSON` using a non-method alias for all non-duration fields and `json.RawMessage` duration fields, so either a JSON number or a quoted Go duration parses without recursive unmarshalling or dropped aliases.

**Tech Stack:** Go 1.25, `encoding/json`, `time.Duration`, `net/http/httptest`, Testify.

**Spec:** `docs/superpowers/specs/2026-08-26-alert-control-plane-design.md`; task directive: backwards-compatible duration serialization for `alert.AlertRule`.

## Global Constraints

- HTTP serialization keeps duration strings exact so JavaScript clients never lose integer precision.
- Typed Go clients must decode both prior numeric-nanosecond payloads and current duration strings.
- Decode only through `AlertRule.UnmarshalJSON`; do not alter request-side `ruleInput` behavior.
- The regression test must deserialize an actual HTTP response into `alert.AlertRule`.

---

## File Structure

| Path | Responsibility |
| --- | --- |
| `backend/internal/alert/model.go` | Defines the dual-format `AlertRule` JSON decoder alongside the existing encoder. |
| `backend/internal/controlplane/http_test.go` | Proves a typed client can decode a real string-duration HTTP response. |
| `backend/internal/alert/model_test.go` | Proves legacy numeric-nanosecond payloads remain accepted. |
| `docs/duration-fix-report.md` | Records the completed compatibility fix and verification evidence. |

### Task 1: Lock the decoder contract with failing tests

**Files:**
- Modify: `backend/internal/controlplane/http_test.go`
- Modify: `backend/internal/alert/model_test.go`

- [ ] Add an HTTP test that gets a rule response with long duration strings, decodes it directly into `alert.AlertRule`, and asserts all three durations plus a non-duration alias field.
- [ ] Add a table-driven model test that decodes literal JSON in both string and numeric-nanosecond formats and asserts the same literal durations.
- [ ] Run `D:\AI\codex\workspace\数据库运维管理系统\.tooling\go\bin\go.exe test ./internal/alert ./internal/controlplane -run 'Test.*AlertRule.*Duration|TestRuleResponsesSerializeLongDurations' -count=1` from `backend`; expect string-response decoding to fail before the implementation.

### Task 2: Implement the minimal dual-format decoder

**Files:**
- Modify: `backend/internal/alert/model.go`

- [ ] Define a private alias that has no JSON methods, embed it in a wire struct with `json.RawMessage` for `evaluation_every`, `lookback_window`, and `for`.
- [ ] Decode non-duration fields through the alias, parse each duration raw message first as a quoted Go duration and otherwise as an exact `int64` nanosecond count, and assign the parsed values only after all parsing succeeds.
- [ ] Re-run the focused Go test command; expect it to pass.

### Task 3: Verify, document, and commit

**Files:**
- Create: `docs/duration-fix-report.md`

- [ ] Run `D:\AI\codex\workspace\数据库运维管理系统\.tooling\go\bin\go.exe test ./...` from `backend`.
- [ ] Run the Node suite with `node --test tests/*.test.js` from the worktree root.
- [ ] Run `gofmt -w backend/internal/alert/model.go backend/internal/alert/model_test.go backend/internal/controlplane/http_test.go`, `git diff --check`, and inspect the staged diff.
- [ ] Append the root cause, compatibility contract, and actual command results to `docs/duration-fix-report.md`; commit only the compatibility files and report with `git commit -m "fix(alerts): decode duration response formats"`.
