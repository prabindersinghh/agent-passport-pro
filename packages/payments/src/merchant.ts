/**
 * Merchant identity normalization. Attackers register look-alike merchants
 * ("pаypal-store" with a Cyrillic 'а', "amaz0n") so a human or allowlist
 * glancing at the name sees a trusted brand. We compare *skeletons*.
 */

const CONFUSABLES: Record<string, string> = {
  // Cyrillic
  'а': 'a', 'в': 'b', 'е': 'e', 'ё': 'e', 'к': 'k', 'м': 'm', 'н': 'h', 'о': 'o', 'р': 'p',
  'с': 'c', 'т': 't', 'у': 'y', 'х': 'x', 'і': 'i', 'ј': 'j', 'ѕ': 's', 'ԁ': 'd', 'ɡ': 'g',
  // Greek
  'α': 'a', 'β': 'b', 'ε': 'e', 'ι': 'i', 'κ': 'k', 'ν': 'v', 'ο': 'o', 'ρ': 'p', 'τ': 't',
  'υ': 'u', 'χ': 'x',
  // Digits / symbols commonly swapped
  '0': 'o', '1': 'l', '3': 'e', '5': 's', '|': 'l', '$': 's', '@': 'a',
};

/** Canonical merchant id: NFKC, lowercase, trimmed, internal whitespace collapsed. */
export function normalizeMerchantId(raw: string): string {
  return raw.normalize('NFKC').toLowerCase().trim().replace(/\s+/g, ' ');
}

/** Visual skeleton used only for look-alike detection — never as an identity. */
export function merchantSkeleton(raw: string): string {
  let s = normalizeMerchantId(raw)
    .normalize('NFKD')
    .replace(/[̀-ͯ​-‏⁠﻿]/g, ''); // strip diacritics + zero-width
  s = [...s].map((ch) => CONFUSABLES[ch] ?? ch).join('');
  return s
    .replace(/rn/g, 'm')
    .replace(/vv/g, 'w')
    .replace(/[^a-z0-9]/g, '')
    .replace(/l/g, 'i'); // collapse l/i/1 family
}

/** True when `candidate` is not `known` but renders like it. */
export function isLookalike(candidate: string, known: string): boolean {
  const a = normalizeMerchantId(candidate);
  const b = normalizeMerchantId(known);
  if (a === b) return false;
  return merchantSkeleton(a) === merchantSkeleton(b);
}

export function hasMixedScripts(raw: string): boolean {
  const latin = /[a-z]/i.test(raw);
  const other = /[Ͱ-ϿЀ-ӿ]/.test(raw);
  return latin && other;
}
