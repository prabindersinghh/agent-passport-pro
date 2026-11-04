# Spend Firewall

`@agent-passport/payments` — a policy enforcement point between an AI agent and a payment provider.

A payment capture is the clearest example of an irreversible agent action: once funds are captured, no later refusal, apology or log line brings them back. The Spend Firewall makes the capture the **last** step of a pipeline the agent cannot influence, and turns every uncertain case into a reversible hold.

---

## Design rules

1. **Assume the agent is compromised.** Every check must hold even if the model does exactly what injected text tells it.
2. **Authority comes from the human, in writing.** A signed task mandate is the only source of spending power. The agent carries it; it cannot widen it.
3. **Deterministic layers decide. Model-based layers may only escalate.** An LLM judge reads attacker-controlled text, so it is itself injectable. Its verdict is clamped: it can send a payment to a human, never wave one through.
4. **Hold first, capture last.** Funds are authorized (held) before any human is asked, and voided on rejection, timeout or error. Capture is called once, after every check, with a provider-side idempotency key.
5. **Unknown means stop.** Any capture error — timeout, reset, 5xx — is treated as uncertain and never retried blindly. The firewall asks the provider; a still-held authorization is voided and the void confirmed before the budget is released. If it still cannot tell, the payment is marked `needs_reconciliation` and the mandate is frozen.
6. **Approvals are bound to the exact payment.** Approval is valid for one hold — one amount, one merchant, one payee — and is claimed atomically, once.

---

## Pipeline

```
 agent ──► pay(request)
             │
             ▼
  1 validation ─── strict schema · decimal-string money · ISO 4217 · no unknown fields
             │
  2 mandate ────── HMAC signature · expiry · bound agent · frozen/revoked
             │
  3 passport ───── agent identity + capability + project policy (core gateway)
             │
  4 intent ─────── heuristic (+ optional LLM) ──► can only ESCALATE
             │
  ┌──────────┴──────────── single IMMEDIATE SQLite transaction ─────────────┐
  │ 5 spend policy ─ currency · blocked categories · per-tx · 24h · task    │
  │                  budget · merchant allowlist · approval threshold       │
  │ 6 risk ───────── velocity · look-alike/homoglyph · payee change ·       │
  │                  duplicate · split purchase · amount anomaly ·          │
  │                  merchant directory (declared vs registered category)   │
  │ reserve budget ─ row inserted as reserved / pending_approval / blocked  │
  └──────────┬──────────────────────────────────────────────────────────────┘
             │
        any BLOCK ──► blocked (nothing reaches the provider)
             │
     provider.authorize()  ← funds held, reversible
             │
     any ESCALATE ──► pending_approval ──► human (approver credential)
             │                              ├─ approve ──► capture
             │                              ├─ reject  ──► void
             │                              └─ timeout ──► void
             ▼
     provider.capture()  ← irreversible, once, idempotent
```

Every step writes to the append-only audit log (`.agent/audit.jsonl`) with the findings that drove the decision.

---

## Concepts

### Mandate

Issued by the human before the task starts:

```bash
agent-passport mandate issue \
  --agent shopper \
  --task "Book a hotel in Goa for 2 nights, 12–14 Dec" \
  --budget 300.00 --currency USD \
  --categories travel.lodging \
  --merchants taj-goa.example \
  --approval-over 100.00 --ttl 60
```

Produces `apm1.<payload>.<hmac>`. Fields: `agent_id`, `task`, `currency`, `max_total_minor`, `max_per_tx_minor`, `approval_over_minor`, `allowed_categories`, `allowed_merchants`, `issued_at`, `expires_at`. The schema is strict, so nothing can be added to a mandate after signing.

The signing key and the approver token live **outside the project tree** (`$AGENT_PASSPORT_HOME`, default `~/.agent-passport`), so an agent with `filesystem.read` on `./**` cannot read them.

### Spend policy

Organization or project limits every mandate is checked against (`.agent/spend-policy.yaml`). A mandate can be narrower, never wider.

```yaml
apiVersion: agentpassport.dev/v1
kind: SpendPolicy
metadata: { id: acme }
allowed_currencies: [USD, INR]
blocked_categories: [gift_card, crypto, money_transfer, gambling, prepaid_card, securities]
defaults:
  per_tx:        { USD: "500.00", INR: "40000.00" }
  daily:         { USD: "1000.00", INR: "80000.00" }
  approval_over: { USD: "100.00", INR: "8000.00" }
agents:
  shopper:
    approval_over: { USD: "50.00" }
new_merchant: approval        # allow | approval | deny
merchants:                    # registry: category and payee are looked up, not trusted
  taj-goa.example: { category: travel.lodging, payee_email: payments@tajgoa.example }
velocity: { max_tx: 5, window_minutes: 10 }
split_detection: { window_minutes: 60 }
anomaly: { multiple_of_median: 3, min_history: 3 }
approval_ttl_minutes: 15
provider_timeout_ms: 8000
```

### Findings

Each layer returns findings with a severity:

| Severity | Effect |
|---|---|
| `block` | Payment rejected before any provider call |
| `escalate` | Funds held; a human must approve within `approval_ttl_minutes` |
| `info` | Recorded only |

The finding codes (`CATEGORY_BLOCKED`, `LOOKALIKE_MERCHANT`, `SPLIT_PURCHASE`, `CAPTURE_UNCERTAIN`, …) appear in the API response, the audit log and the red-team report.

---

## Integration

### MCP (any MCP-capable agent)

```json
{
  "mcpServers": {
    "pay": {
      "command": "npx",
      "args": ["agent-passport-pay-mcp"],
      "env": {
        "AGENT_PASSPORT_CWD": "/path/to/project",
        "AGENT_PASSPORT_AGENT": "shopper",
        "AGENT_PASSPORT_MANDATE": "apm1....",
        "PAYPAL_CLIENT_ID": "...", "PAYPAL_CLIENT_SECRET": "...", "PAYPAL_VAULT_ID": "..."
      }
    }
  }
}
```

The agent sees two tools, `pay` and `payment_status`. It does not see provider credentials, the mandate token, or any approval tool. Identity and mandate come from process configuration, not from tool arguments. Without PayPal variables the server uses the mock provider.

### HTTP

Start with `AGENT_PASSPORT_PAYMENTS=1 agent-passport-http`.

| Route | Caller | Notes |
|---|---|---|
| `POST /v1/payments` | agent | `200` captured · `202` held for approval · `403` blocked |
| `GET /v1/payments/:id` | agent | status only |
| `GET /v1/payments-pending` | approver | `Authorization: Bearer <approver token>` |
| `POST /v1/payments/:id/approve` | approver | body `{ "decidedBy": "alice@acme" }` |
| `POST /v1/payments/:id/reject` | approver | voids the hold |

### Library

```ts
import { SpendFirewall, MockPayPalProvider } from '@agent-passport/payments';

const fw = new SpendFirewall({ cwd: process.cwd(), provider: new MockPayPalProvider() });
const r = await fw.pay({
  agent_id: 'shopper',
  mandate: process.env.AGENT_PASSPORT_MANDATE,
  merchant: { id: 'taj-goa.example', name: 'Taj Goa', category: 'travel.lodging' },
  amount: '240.00',
  currency: 'USD',
  description: '2 nights',
  idempotency_key: 'booking-8841-goa',
});
// r.outcome: captured | pending_approval | blocked | failed | needs_reconciliation
```

---

## Deployment model

The firewall is only a boundary if the agent cannot go around it.

- Run it as a **separate process** (MCP server or HTTP gateway) holding the provider credentials. The agent process holds none.
- Give the approver token to humans only (CLI on their machine, or an approval UI behind your SSO). The agent never receives it.
- Put `.agent/spend-policy.yaml` under code review like any other policy.

In-process library use is convenient for tests and demos but shares a trust domain with the agent.

---

## Providers

| Provider | Status |
|---|---|
| `MockPayPalProvider` | Used by all tests, the demo and the red-team suite. Models Orders v2 `intent=AUTHORIZE`: authorize → capture (irreversible, idempotent per request id) → void. Fault injection: hung authorize, hung capture, capture lost after success, declined capture. |
| `PayPalProvider` | **Experimental, not exercised in CI.** Orders v2 + Payments v2 against `api-m.sandbox.paypal.com`. Server-side authorization needs a vaulted PayPal payment method (`PAYPAL_VAULT_ID`). |

---

## Limitations

Stated plainly, because they matter for anyone adopting this:

- **Category is only as good as its source.** If a merchant is not in the directory, the agent's declared category is checked for consistency (description heuristics, new-merchant rule) but not proven. In production, category should come from the provider's merchant category code.
- **New-merchant escalation is load-bearing.** The ablation shows PI-05 (injection that also fools the LLM judge) is stopped by that rule alone. Setting `new_merchant: allow` removes that protection.
- **Human approval is a control, not a guarantee.** A tired approver can approve a bad payment. The firewall shows the approver the merchant, payee, category, amount and every finding, and limits exposure with the task budget, but it cannot fix judgment.
- **The ledger is local.** Budgets are enforced per firewall deployment. Several independent firewall instances for the same agent need a shared ledger (Postgres) — not implemented.
- **Mock-provider evidence.** All measured results use the mock provider. They show the firewall's logic; they do not prove the PayPal adapter.
- **Payee.** Funds go to the payee account sent to the provider. Register `payee_email` for merchants in the directory; an unregistered, agent-supplied payee always escalates to a human.
- **`GET /v1/payments/:id` is not scoped to the calling agent** (status only).
- **Heuristic intent checks are pattern-based** and easy to evade on their own. They are defense in depth; the ablation confirms no attack relied on them alone.
