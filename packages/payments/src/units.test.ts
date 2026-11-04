import { describe, it, expect } from 'vitest';
import { parseMajor, MoneyError } from './money.js';
import { isLookalike, merchantSkeleton, hasMixedScripts } from './merchant.js';
import { buildMandate, signMandate, verifyMandate, MandateError } from './mandate.js';

describe('money', () => {
  it('parses exact decimal strings into minor units', () => {
    expect(parseMajor('49.99', 'USD')).toBe(4999);
    expect(parseMajor('49.9', 'USD')).toBe(4990);
    expect(parseMajor('5000', 'JPY')).toBe(5000);
  });
  it('rejects anything ambiguous', () => {
    for (const bad of ['-1', '0', '1e3', '49.999', ' 1', '1,00', 'NaN', 'Infinity', '0x10', '01.00', '']) {
      expect(() => parseMajor(bad, 'USD'), bad).toThrow(MoneyError);
    }
    expect(() => parseMajor('1.5', 'JPY')).toThrow(MoneyError);
    expect(() => parseMajor('1.00', 'XXX')).toThrow(MoneyError);
    expect(() => parseMajor(12 as unknown as string, 'USD')).toThrow(MoneyError);
  });
});

describe('merchant look-alikes', () => {
  it('detects digit swaps, homoglyphs and zero-width tricks', () => {
    expect(isLookalike('taj-g0a.example', 'taj-goa.example')).toBe(true);
    expect(isLookalike('таj-goa.example', 'taj-goa.example')).toBe(true);
    expect(normalizeMerchantId('taj\u200b-goa.example')).toBe('taj-goa.example'); // zero-width stripped: same id, not a twin
    expect(isLookalike('rnarriott.example', 'marriott.example')).toBe(true);
    expect(isLookalike('taj-goa.example', 'taj-goa.example')).toBe(false);
    expect(isLookalike('hilton.example', 'taj-goa.example')).toBe(false);
    expect(hasMixedScripts('Таj Goa')).toBe(true);
    expect(merchantSkeleton('PAYPAL')).toBe(merchantSkeleton('paypa1'));
  });
});

describe('mandate', () => {
  const key = Buffer.alloc(32, 1);
  const m = buildMandate({ agentId: 'shopper', task: 'hotel', issuedBy: 'me', currency: 'USD', maxTotal: '300.00', allowedCategories: ['travel.lodging'], ttlMinutes: 10 });
  const token = signMandate(m, key);

  it('verifies a genuine mandate', () => {
    expect(verifyMandate(token, key, { agentId: 'shopper' }).max_total_minor).toBe(30000);
  });
  it('rejects tampering, wrong key, wrong agent, expiry, garbage', () => {
    const [v, p, s] = token.split('.');
    const body = JSON.parse(Buffer.from(p, 'base64url').toString());
    body.max_total_minor = 1e9;
    const tampered = `${v}.${Buffer.from(JSON.stringify(body)).toString('base64url')}.${s}`;
    const expect_ = (t: unknown, opts: Parameters<typeof verifyMandate>[2], k = key) => expect(() => verifyMandate(t, k, opts)).toThrow(MandateError);
    expect_(tampered, { agentId: 'shopper' });
    expect_(token, { agentId: 'shopper' }, Buffer.alloc(32, 2));
    expect_(token, { agentId: 'researcher' });
    expect_(token, { agentId: 'shopper', now: new Date(Date.now() + 11 * 60_000) });
    expect_('apm1.x.y', { agentId: 'shopper' });
    expect_(undefined, { agentId: 'shopper' });
    expect_(token, { agentId: 'shopper', isRevoked: () => true });
  });
  it('mandate schema is strict: extra fields cannot be signed in', () => {
    expect(() => signMandate({ ...m, unlimited: true } as never, key)).toThrow();
  });
});

import { normalizeMerchantId, lookupDirectory } from './merchant.js';
describe('merchant canonicalisation + directory lookup', () => {
  it('collapses host variants to one id', () => {
    for (const v of ['giftcards-now.example', 'GiftCards-Now.Example.', 'www.giftcards-now.example', 'https://www.giftcards-now.example:443/checkout?x=1', 'user@giftcards-now.example', ' giftcards-now.example​ ']) {
      expect(normalizeMerchantId(v), v).toBe('giftcards-now.example');
    }
  });
  it('subdomains inherit the registered entry; unrelated domains do not', () => {
    const dir = { 'GiftCards-Now.example': { category: 'gift_card' } };
    expect(lookupDirectory(dir, 'shop.giftcards-now.example:443')?.entry.category).toBe('gift_card');
    expect(lookupDirectory(dir, 'giftcards-now.example.evil.example')).toBeUndefined();
    expect(lookupDirectory(dir, 'example')).toBeUndefined();
    expect(lookupDirectory({ __proto__: 1 } as never, 'constructor')).toBeUndefined();
  });
});
