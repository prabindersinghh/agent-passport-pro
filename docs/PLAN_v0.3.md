# PLAN v0.3 — Approval hardening + Spend Firewall

Status: implemented on branch `v0.3-irreversibility-firewall`, pending maintainer review before merge.

## Why

1. Red-teaming v0.2.0 showed approvals were not bound to the action's arguments and could be self-granted, reused or widened. Every protected action depends on approvals, so this comes first.
2. Payments are the highest-stakes irreversible action agents are being given. They need a dedicated enforcement point with domain controls (holds, budgets, payee verification), not just an allow/deny rule.

## Scope

| Area | Change |
|---|---|
| core | `binding.ts` (canonical JSON, argument hash, approver token); `approval.ts` (hash, pending TTL, approver scope, atomic claim, self-approval guard, migration); gateway claims before execution; payment actions in catalog |
| http | approver bearer token on grant/deny; optional `/v1/payments` routes |
| payments (new) | money, merchant, mandate, spend-policy, ledger, checks, intent, firewall, providers (mock + PayPal experimental), MCP server, sandbox, red-team scenarios + report |
| cli | `demo payments`, `redteam`, `mandate issue`; approve shows bound arguments |
| python sdk | `action_binding_hash`, approval hash check, updated conformance fixtures |
| ci | red-team suite and payment demo run on every push |

## Compatibility

- Existing `approvals.db` files migrate in place (additive columns).
- High-risk approvals created without an argument hash no longer satisfy policy. The CLI and gateway now always attach one.

## Next

- Shared ledger for multi-instance deployments
- Approval UI (web / Slack) on top of the HTTP approver routes
- Argument-aware mapping in `mcp-proxy` so third-party payment MCP servers can sit behind the firewall
- Live PayPal sandbox run in CI
