/**
 * Money is always integer minor units + ISO 4217 code. Floats never touch a balance.
 * Parsing is strict: "49.99" USD ok, "49.999" USD rejected, "1e3" rejected, "-5" rejected.
 */

/** ISO 4217 minor-unit exponents for currencies we accept. Unknown currency = reject. */
export const CURRENCY_EXPONENT: Readonly<Record<string, number>> = Object.freeze({
  USD: 2, EUR: 2, GBP: 2, INR: 2, AUD: 2, CAD: 2, SGD: 2, CHF: 2, SEK: 2, NOK: 2,
  DKK: 2, PLN: 2, NZD: 2, HKD: 2, MXN: 2, BRL: 2, ILS: 2, PHP: 2, THB: 2, MYR: 2,
  JPY: 0, KRW: 0, HUF: 2, CZK: 2, TWD: 2,
});

/** Hard ceiling on any single amount, in minor units, regardless of policy (overflow guard). */
export const MAX_MINOR = 1_000_000_000_00; // 1 billion major units

export interface Money {
  amount_minor: number;
  currency: string;
}

export class MoneyError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'MoneyError';
  }
}

export function assertCurrency(code: unknown): string {
  if (typeof code !== 'string' || !/^[A-Z]{3}$/.test(code) || !(code in CURRENCY_EXPONENT)) {
    throw new MoneyError(`Unsupported or malformed currency: ${JSON.stringify(code)}`);
  }
  return code;
}

/** Parse a decimal string in major units ("49.99") into integer minor units. */
export function parseMajor(value: unknown, currency: string): number {
  const cur = assertCurrency(currency);
  if (typeof value !== 'string') throw new MoneyError('Amount must be a decimal string');
  const exp = CURRENCY_EXPONENT[cur];
  const re = exp === 0 ? /^(0|[1-9]\d{0,14})$/ : new RegExp(`^(0|[1-9]\\d{0,14})(\\.\\d{1,${exp}})?$`);
  if (!re.test(value)) throw new MoneyError(`Malformed amount '${value}' for ${cur}`);
  const [whole, frac = ''] = value.split('.');
  const minor = Number(whole) * 10 ** exp + Number(frac.padEnd(exp, '0') || '0');
  return assertMinor(minor);
}

export function assertMinor(value: unknown): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value)) {
    throw new MoneyError('Amount (minor units) must be a safe integer');
  }
  if (value <= 0) throw new MoneyError('Amount must be positive');
  if (value > MAX_MINOR) throw new MoneyError('Amount exceeds absolute ceiling');
  return value;
}

export function money(amount: string, currency: string): Money {
  return { amount_minor: parseMajor(amount, currency), currency: assertCurrency(currency) };
}

export function formatMoney(m: Money): string {
  const exp = CURRENCY_EXPONENT[m.currency] ?? 2;
  const major = (m.amount_minor / 10 ** exp).toFixed(exp);
  return `${m.currency} ${major}`;
}

export function toMajorString(m: Money): string {
  const exp = CURRENCY_EXPONENT[m.currency] ?? 2;
  return (m.amount_minor / 10 ** exp).toFixed(exp);
}
