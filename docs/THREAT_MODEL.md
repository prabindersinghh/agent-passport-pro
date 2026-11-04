# Threat model

Scope: Agent Passport v0.3 core gateway and Spend Firewall.

## Assets

| Asset | Why it matters |
|---|---|
| Captured funds | Irreversible once captured |
| Provider credentials (PayPal client secret, vault id) | Direct access to funds, bypassing every control |
| Mandate signing key | Lets the holder mint spending authority |
| Approver token | Lets the holder convert a hold into a capture |
| Policy files (`.agent/*.yaml`) | Define what is allowed |
| Ledger and audit log | Source of truth for budgets and investigation |

## Trust boundaries

```
  untrusted                                   │ trusted
  ────────────────────────────────────────────┼───────────────────────────────
  web pages, emails, documents, tool output   │ human who issues the mandate
  the LLM and its reasoning                   │ human approver (holds token)
  the agent process and its tool arguments    │ firewall process (holds provider creds)
  merchant names, descriptions, categories    │ policy files under code review
  an LLM judge (reads untrusted text)         │ provider's own capture semantics
```

Anything on the left can be controlled by an attacker through prompt injection. Nothing on the left can grant authority.

## Attacker capabilities assumed

- Full control of the agent's tool calls (it does what the injected text says).
- Can read anything the agent can read, including its context and the project tree.
- Can call every agent-facing endpoint and tool, any number of times, concurrently.
- Can craft merchant names with homoglyphs, zero-width characters and look-alike domains.
- Can influence an LLM judge's output completely.
- Can cause provider timeouts and lost responses (or exploit ones that happen naturally).

## Out of scope

- Compromise of the firewall host, the approver's machine, or the provider.
- A human approver who deliberately approves fraud.
- Merchants that are genuinely what they claim but deliver nothing (a commercial dispute, not an authorization failure).

## Controls mapped to threats

| Threat | Control | Evidence |
|---|---|---|
| Injected purchase outside the task | Mandate categories / merchants, blocked categories, intent check | PI-01, PI-02, PI-06 |
| Look-alike or homoglyph merchant | Skeleton comparison against trusted merchants, mixed-script rejection | PI-03, PI-04 |
| LLM judge fooled by the same injection | Judge clamped to escalate-only; deterministic rules decide | PI-05, ablation row `intent` |
| Agent lies about category | Merchant directory | PI-06 |
| Payee swap / invoice redirection | Payee bound to merchant history and directory | AB-01 |
| Agent approves itself | Approver token outside agent trust domain; approver ≠ agent | AB-02, AB-03, AB-05 |
| Approval reused or replayed | Approval bound to one hold, claimed atomically, once | AB-04, core `approval-hardening.test.ts` |
| Old request approved out of context | Hold TTL; unanswered = voided | AB-06 |
| Split purchases, runaway loops | Split detection, duplicate detection, velocity | BL-01, BL-04 |
| Budget race | Check-and-reserve in one IMMEDIATE transaction | BL-03 |
| Currency confusion | Mandate currency binding | BL-05 |
| Mandate tampering, forgery, theft, expiry | HMAC, strict schema, agent binding, expiry | MD-01 … MD-04 |
| Payment-capable mandate given to wrong agent | Passport capability check | MD-05 |
| Parser tricks, smuggled fields | Strict schema, decimal-string money | IN-01, IN-02 |
| Idempotency key abuse | Key bound to payment hash | IN-03 |
| Double charge on retry | Idempotency + status reconciliation, never blind retry | PF-01 |
| Capture state unknown | `needs_reconciliation`, mandate frozen | PF-02 |
| Provider hang | Timeouts; failed hold = nothing captured | PF-03 |

## Vulnerabilities found in v0.2.0 and fixed in v0.3.0

Found by red-teaming our own previous release (commit `640b4c5`) before building the payments layer. Each has a regression test in `packages/core/src/approval-hardening.test.ts` or `packages/http/src/server.test.ts`.

| ID | Issue in v0.2.0 | Impact | Fix |
|---|---|---|---|
| BYPASS-1 | Approvals matched on action + resource only | Approve `merge sha=SAFE`, execute `merge sha=MALICIOUS` | Approval stores `sha256(canonical action, resource, arguments)`; must match exactly |
| BYPASS-2 | `grant()` accepted any `decidedBy`, including the requesting agent | Agent approves its own request | Self-approval rejected |
| BYPASS-3 | Once-approvals consumed only after a *successful* run | A failing or concurrent action could run repeatedly on one approval | Claimed atomically **before** execution, not refunded |
| BYPASS-4 | Requester chose scope; `resource: "*"` + `permanent` accepted | One approval covers every future high-risk action | Approver chooses scope; high-risk defaults to `once`; unbound grants never satisfy high-risk actions |
| BYPASS-5 | HTTP `/v1/approvals/:id/grant` unauthenticated on the same port the agent uses | Agent approves over HTTP | Approver bearer token required; routes disabled when no token is configured |
| — | Pending approvals never expired | Stale requests approvable days later | 15-minute pending TTL |
| — | Non-finite numbers in tool arguments | Canonicalization ambiguity | Fail closed |
