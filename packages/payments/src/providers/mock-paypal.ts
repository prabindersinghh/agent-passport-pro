import { v4 as uuidv4 } from 'uuid';
import type { Hold, HoldRequest, PaymentProvider, ProviderStatus } from './provider.js';
import type { Money } from '../money.js';

export interface MockFaults {
  /** authorize() never resolves (simulates a hung provider). */
  hangAuthorize?: boolean;
  /** capture() succeeds on the provider but the response is lost (timeout after money moved). */
  captureSucceedsThenHangs?: boolean;
  /** capture() hangs and the provider never captured. */
  hangCapture?: boolean;
  captureFails?: boolean;
}

export interface MovedMoney {
  captureId: string;
  authorizationId: string;
  merchant_id: string;
  amount: Money;
  at: string;
}

/**
 * In-memory stand-in for PayPal Orders v2 (intent=AUTHORIZE) + Payments v2.
 * Faithful to the property that matters: capture is irreversible and idempotent
 * per PayPal-Request-Id. `moved` is the ground truth for "did money leave?".
 */
export class MockPayPalProvider implements PaymentProvider {
  readonly name = 'mock-paypal';
  readonly moved: MovedMoney[] = [];
  private auths = new Map<string, { req: HoldRequest; status: ProviderStatus; captureId?: string }>();
  private captureByRequestId = new Map<string, string>();
  faults: MockFaults = {};

  async authorize(req: HoldRequest): Promise<Hold> {
    if (this.faults.hangAuthorize) return new Promise(() => {});
    const authorizationId = `AUTH-${uuidv4().slice(0, 8).toUpperCase()}`;
    this.auths.set(authorizationId, { req, status: 'held' });
    return {
      orderId: `ORDER-${uuidv4().slice(0, 8).toUpperCase()}`,
      authorizationId,
      expiresAt: new Date(Date.now() + 3 * 24 * 3600_000).toISOString(),
    };
  }

  async capture(authorizationId: string, requestId: string): Promise<{ captureId: string }> {
    const prior = this.captureByRequestId.get(requestId);
    if (prior) return { captureId: prior }; // provider-side idempotency
    const a = this.auths.get(authorizationId);
    if (!a) throw new Error('AUTHORIZATION_NOT_FOUND');
    if (a.status === 'voided') throw new Error('AUTHORIZATION_VOIDED');
    if (a.status === 'captured') return { captureId: a.captureId! };
    if (this.faults.captureFails) throw new Error('INSTRUMENT_DECLINED');
    if (this.faults.hangCapture) return new Promise(() => {});
    const captureId = `CAP-${uuidv4().slice(0, 8).toUpperCase()}`;
    a.status = 'captured';
    a.captureId = captureId;
    this.captureByRequestId.set(requestId, captureId);
    this.moved.push({
      captureId,
      authorizationId,
      merchant_id: a.req.payee.merchant_id,
      amount: a.req.amount,
      at: new Date().toISOString(),
    });
    if (this.faults.captureSucceedsThenHangs) return new Promise(() => {});
    return { captureId };
  }

  async void(authorizationId: string): Promise<void> {
    const a = this.auths.get(authorizationId);
    if (!a) return;
    if (a.status === 'captured') throw new Error('CANNOT_VOID_CAPTURED');
    a.status = 'voided';
  }

  async status(authorizationId: string): Promise<ProviderStatus> {
    return this.auths.get(authorizationId)?.status ?? 'unknown';
  }

  /** Total money that actually left, per currency. */
  totalMoved(): Record<string, number> {
    const out: Record<string, number> = {};
    for (const m of this.moved) out[m.amount.currency] = (out[m.amount.currency] ?? 0) + m.amount.amount_minor;
    return out;
  }
}
