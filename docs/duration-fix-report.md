# Duration Fix Report

## 2026-08-27 — AlertRule typed-client JSON compatibility

- Root cause: `e7657b1` changed `AlertRule` duration output to exact Go duration strings, while typed Go clients still relied on default `time.Duration` numeric JSON decoding.
- Fix: `AlertRule.UnmarshalJSON` now decodes `evaluation_every`, `lookback_window`, and `for` as either exact duration strings or legacy `int64` nanoseconds. A private alias carries every other field, avoiding recursive unmarshalling and preserving ordinary JSON aliases.
- Regression coverage: direct decoding of a live GET rule response into `alert.AlertRule`, plus literal string and legacy numeric duration payloads with policy-ID and label aliases.
- Verification: `D:\AI\codex\workspace\数据库运维管理系统\.tooling\go\bin\go.exe test ./...` from `backend` passed; `node --test tests/*.test.js` passed (54 tests).
