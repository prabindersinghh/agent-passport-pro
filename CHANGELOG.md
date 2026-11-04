# Changelog

**Session log:** [docs/CHANGELOG.md](docs/CHANGELOG.md)

## 0.3.0 — 2026-11-04

- **Security:** fixed five approval bypasses in v0.2.0 (argument-bound approvals, no self-approval, atomic once-claim before execution, approver-chosen scope, authenticated grant endpoint) plus pending-approval expiry. See docs/THREAT_MODEL.md.
- **New package `@agent-passport/payments`:** Spend Firewall — signed mandates, spend policy, risk rules, escalate-only intent checks, authorize-then-capture, reconciliation on uncertain capture, MCP server, HTTP routes.
- **Red-team harness:** 31 scenarios, no-guard baseline, per-layer ablation; runs in CI.
- **CLI:** `demo payments`, `redteam`, `mandate issue`.
- **Breaking:** high-risk approvals must be bound to arguments; unbound wildcard approvals no longer satisfy them. `consumeOnce` is now `claim` (alias kept).

## 0.2.0 — 2026-08-26

Security hardening, MCP proxy, HTTP gateway, native Python policy, runtime integration docs. See docs/CHANGELOG.md.

## 0.1.0 — 2026-08-26

Initial release: policy engine, gateway, CLI, adapters, SDKs, demo.
