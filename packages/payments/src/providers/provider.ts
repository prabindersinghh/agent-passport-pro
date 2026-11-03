import type { Money } from '../money.js';

/**
 * Two-phase payment provider. authorize() places a hold (reversible);
 * capture() moves money (IRREVERSIBLE); void() releases a hold.
 * The firewall only ever calls capture() after every check has passed.
 */
export interface HoldRequest {
  amount: Money;
  payee: { merchant_id: string; email?: string };
  description: string;
  /** Provider-side idempotency key (PayPal-Request-Id). */
  requestId: string;
}

export interface Hold {
  orderId: string;
  authorizationId: string;
  expiresAt?: string;
}

export type ProviderStatus = 'held' | 'captured' | 'voided' | 'unknown';

export interface PaymentProvider {
  readonly name: string;
  authorize(req: HoldRequest): Promise<Hold>;
  capture(authorizationId: string, requestId: string): Promise<{ captureId: string }>;
  void(authorizationId: string): Promise<void>;
  status(authorizationId: string): Promise<ProviderStatus>;
}

export class ProviderTimeoutError extends Error {
  constructor(op: string) {
    super(`Provider ${op} timed out`);
    this.name = 'ProviderTimeoutError';
  }
}

export async function withTimeout<T>(op: string, ms: number, p: Promise<T>): Promise<T> {
  let timer: NodeJS.Timeout | undefined;
  const t = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new ProviderTimeoutError(op)), ms);
  });
  try {
    return await Promise.race([p, t]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}
