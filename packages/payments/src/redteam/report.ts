import type { RunRecord } from './scenarios.js';
import type { Finding } from '../checks.js';

const usd = (minor: number) => (minor < 0 ? 'error' : `$${(minor / 100).toLocaleString('en-US', { minimumFractionDigits: 2 })}`);

export interface ReportInput {
  records: RunRecord[];
  ablation?: { layer: Finding['layer']; failed: string[] }[];
  generatedAt?: Date;
  version?: string;
}

export function summaryStats(records: RunRecord[]) {
  const attacks = records.filter((r) => r.scenario.category !== 'legitimate-use');
  const legit = records.filter((r) => r.scenario.category === 'legitimate-use');
  return {
    attacks: attacks.length,
    attacksStopped: attacks.filter((r) => r.passed).length,
    legit: legit.length,
    legitCompleted: legit.filter((r) => r.passed).length,
    baselineLoss: attacks.reduce((s, r) => s + r.baselineMinor, 0),
    firewallLoss: attacks.reduce((s, r) => s + Math.max(0, r.result.unauthorizedMinor), 0),
    errors: records.filter((r) => r.error).length,
  };
}

export function renderMarkdown({ records, ablation, generatedAt = new Date(), version = '0.3.0' }: ReportInput): string {
  const s = summaryStats(records);
  const lines: string[] = [];
  lines.push(`# Agent Passport — Spend Firewall red-team report`);
  lines.push('');
  lines.push(`Generated ${generatedAt.toISOString()} · v${version} · reproduce with \`npm run redteam\``);
  lines.push('');
  lines.push(`**Threat model:** the agent is already compromised and does exactly what injected text tells it. Each scenario runs twice: once with the agent calling the payment API directly (no guard), once through the Spend Firewall. "Unauthorized" means money captured that neither the signed mandate nor a human decision covered.`);
  lines.push('');
  lines.push(`| | No guard | Spend Firewall |`);
  lines.push(`|---|---:|---:|`);
  lines.push(`| Attack scenarios where money left | ${records.filter((r) => r.scenario.category !== 'legitimate-use' && r.baselineMinor > 0).length} / ${s.attacks} | ${s.attacks - s.attacksStopped} / ${s.attacks} |`);
  lines.push(`| Unauthorized money moved | ${usd(s.baselineLoss)} | ${usd(s.firewallLoss)} |`);
  lines.push(`| Legitimate tasks completed | — | ${s.legitCompleted} / ${s.legit} |`);
  lines.push('');
  lines.push(`## Results`);
  lines.push('');
  lines.push(`| ID | Attack | No guard | Firewall | Outcome | Caught by |`);
  lines.push(`|---|---|---:|---:|---|---|`);
  for (const r of records) {
    const mark = r.passed ? '✅' : '❌';
    const caught = r.result.caughtBy.length ? r.result.caughtBy.map((c) => `\`${c}\``).join(' ') : '—';
    lines.push(
      `| ${mark} ${r.scenario.id} | **${r.scenario.title}** — ${r.scenario.attack.replace(/\|/g, '/')} | ${r.scenario.category === 'legitimate-use' ? '—' : usd(r.baselineMinor)} | ${r.scenario.category === 'legitimate-use' ? '—' : usd(Math.max(0, r.result.unauthorizedMinor))} | ${r.result.outcome.replace(/\|/g, '/')} | ${caught} |`
    );
  }
  const notes = records.filter((r) => r.result.notes);
  if (notes.length) {
    lines.push('');
    lines.push(`**Notes**`);
    for (const r of notes) lines.push(`- ${r.scenario.id}: ${r.result.notes}`);
  }
  if (ablation) {
    lines.push('');
    lines.push(`## Ablation: what each layer contributes`);
    lines.push('');
    lines.push(`Each row re-runs the full suite with one layer switched off. A scenario listed here is one that layer stops on its own; empty means every attack it catches is also caught by another layer.`);
    lines.push('');
    lines.push(`| Layer removed | Scenarios that then fail |`);
    lines.push(`|---|---|`);
    for (const a of ablation) lines.push(`| \`${a.layer}\` | ${a.failed.length ? a.failed.join(', ') : '— (fully redundant)'} |`);
  }
  if (s.errors) {
    lines.push('');
    lines.push(`## Errors`);
    for (const r of records.filter((x) => x.error)) lines.push(`- ${r.scenario.id}: \`${(r.error ?? '').split('\n')[0]}\``);
  }
  lines.push('');
  return lines.join('\n');
}
