# Progress

Last updated: **2026-11-04** (session: v0.3 approval hardening + Spend Firewall, branch `v0.3-irreversibility-firewall`)

---

## Current state

**v0.3.0 — Agent Passport Pro** — approval bypasses fixed; `@agent-passport/payments` Spend Firewall; red-team harness (34 scenarios, 0 unauthorized captures, 3/3 legitimate tasks); 95 TS tests + 16 Python tests passing. PayPal REST adapter present but not run live.

### Previous

**v0.2.0** — MCP proxy, HTTP gateway, security hardening, native Python policy, runtime docs. Published on GitHub with release tag `v0.2.0`.

Baseline commit: `b1f27a2`  
Release tag: `v0.2.0` → `a900e95`
Latest `main`: post-release README + docs polish
Repository: https://github.com/prabindersinghh/agent-passport-pro (continues https://github.com/prabindersinghh/agent-passport)

---

## Built

| Area | Status |
|------|--------|
| Core policy + gateway | ✅ |
| Security normalize + protected paths | ✅ |
| Approval once-consume | ✅ |
| Memory (no authority) | ✅ |
| MCP proxy package | ✅ |
| HTTP gateway package | ✅ |
| GitHub mock + live | ✅ |
| Native Python policy | ✅ |
| Runtime integration docs | ✅ |
| Security tests | ✅ |
| README landing page + logo | ✅ |
| Living docs synced to v0.2.0 | ✅ |

---

## Verified LIVE

| Check | Result |
|-------|--------|
| `npm run build` | exit 0 |
| `npm test` | exit 0 — 37 TS tests |
| `pytest sdk/python/tests` | exit 0 — 14 tests |
| `cli demo` | merge APPROVAL_REQUIRED, deploy DENY |
| `npm run demo` (repo root) | exit 0 — runs example-app |

---

## Verified ONLY IN TESTS

| Item | Location |
|------|----------|
| Path traversal / protected paths | `security.test.ts` |
| Approval consume-once | `security.test.ts` |
| Audit append-only (INV-10) | `security.test.ts` |
| Memory never grants authority (INV-11) | `security.test.ts` |
| MCP proxy deny/allow | `mcp-proxy/proxy.test.ts` |
| HTTP authorize DENY | `http/server.test.ts` |
| Python conformance | `sdk/python/tests` |

---

## Remaining limitations (honest)

1. Live GitHub requires `GITHUB_TOKEN` — demo uses mock by default
2. No proprietary Cursor binary patch — enforcement via MCP/HTTP config
3. Deployment adapter does not call cloud APIs (policy still real)
4. Telemetry/CLI packages still thin on dedicated unit tests
5. npm packages not published — clone + build required

---

## Next (post-release)

1. npm publish packages
2. Optional: OTLP exporter config examples
3. Optional: richer orchestrator controller package

---

## Session log

| Session | Work |
|---------|------|
| 2026-08-26 | v0.2.0 implementation + GitHub release |
| 2026-08-26 | Final QA, README landing page, demo script fix, GitHub metadata |
| 2026-08-26 | README visual polish (centered hero, spacing) |
| 2026-08-26 | README `<pre align="center">` diagrams; ARCHITECTURE/MCP/HTTP/RUNTIME docs synced |
