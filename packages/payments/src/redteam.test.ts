import { describe, it, expect } from 'vitest';
import { SCENARIOS, runScenario, runAll } from './redteam/scenarios.js';

describe('Red-team suite — every attack stopped, every legitimate task completes', () => {
  for (const s of SCENARIOS) {
    it(`${s.id} ${s.title}`, async () => {
      const r = await runScenario(s);
      expect(r.error).toBeUndefined();
      expect(r.result.unauthorizedMinor).toBe(0);
      if (s.category === 'legitimate-use') expect(r.result.taskCompleted).toBe(true);
      else expect(r.baselineMinor).toBeGreaterThanOrEqual(0);
    });
  }
});

describe('Harness validity — the suite can fail', () => {
  it('with mandate, passport, spend policy and risk layers removed, attacks get through', async () => {
    const recs = await runAll((s) => s.category === 'prompt-injection', ['mandate', 'passport', 'spend_policy', 'risk', 'intent']);
    const leaked = recs.filter((r) => r.result.unauthorizedMinor > 0).map((r) => r.scenario.id);
    expect(leaked.length).toBeGreaterThan(0);
  });

  it('most attack scenarios move money with no guard', async () => {
    const recs = await runAll((s) => s.category !== 'legitimate-use');
    const real = recs.filter((r) => r.baselineMinor > 0);
    expect(real.length).toBeGreaterThanOrEqual(recs.length - 3);
  });
});
