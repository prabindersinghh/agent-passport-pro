import type { Hold, HoldRequest, PaymentProvider, ProviderStatus } from './provider.js';
import { toMajorString } from '../money.js';

/**
 * PayPal REST adapter (Orders v2 intent=AUTHORIZE, Payments v2 capture/void).
 *
 * EXPERIMENTAL — not exercised in CI. Server-side authorization without a buyer
 * redirect requires a vaulted PayPal payment method (`vaultId`); without it,
 * PayPal returns PAYER_ACTION_REQUIRED and this adapter throws.
 * Sandbox: https://api-m.sandbox.paypal.com
 */
export interface PayPalConfig {
  clientId: string;
  clientSecret: string;
  vaultId: string;
  baseUrl?: string;
}

export class PayPalProvider implements PaymentProvider {
  readonly name = 'paypal';
  private token?: { value: string; exp: number };

  constructor(private readonly cfg: PayPalConfig) {}

  static fromEnv(): PayPalProvider | undefined {
    const { PAYPAL_CLIENT_ID, PAYPAL_CLIENT_SECRET, PAYPAL_VAULT_ID, PAYPAL_BASE_URL } = process.env;
    if (!PAYPAL_CLIENT_ID || !PAYPAL_CLIENT_SECRET || !PAYPAL_VAULT_ID) return undefined;
    return new PayPalProvider({
      clientId: PAYPAL_CLIENT_ID,
      clientSecret: PAYPAL_CLIENT_SECRET,
      vaultId: PAYPAL_VAULT_ID,
      baseUrl: PAYPAL_BASE_URL,
    });
  }

  private get base(): string {
    return this.cfg.baseUrl ?? 'https://api-m.sandbox.paypal.com';
  }

  private async accessToken(): Promise<string> {
    if (this.token && this.token.exp > Date.now() + 30_000) return this.token.value;
    const res = await fetch(`${this.base}/v1/oauth2/token`, {
      method: 'POST',
      headers: {
        Authorization: `Basic ${Buffer.from(`${this.cfg.clientId}:${this.cfg.clientSecret}`).toString('base64')}`,
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: 'grant_type=client_credentials',
    });
    if (!res.ok) throw new Error(`PayPal auth failed: ${res.status}`);
    const body = (await res.json()) as { access_token: string; expires_in: number };
    this.token = { value: body.access_token, exp: Date.now() + body.expires_in * 1000 };
    return body.access_token;
  }

  private async call(path: string, method: string, requestId: string, body?: unknown): Promise<any> {
    const res = await fetch(`${this.base}${path}`, {
      method,
      headers: {
        Authorization: `Bearer ${await this.accessToken()}`,
        'Content-Type': 'application/json',
        'PayPal-Request-Id': requestId,
        Prefer: 'return=representation',
      },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    const text = await res.text();
    const json = text ? JSON.parse(text) : {};
    if (!res.ok) throw new Error(`PayPal ${method} ${path} failed: ${res.status} ${json?.name ?? ''}`);
    return json;
  }

  async authorize(req: HoldRequest): Promise<Hold> {
    const order = await this.call('/v2/checkout/orders', 'POST', req.requestId, {
      intent: 'AUTHORIZE',
      purchase_units: [
        {
          reference_id: req.payee.merchant_id,
          description: req.description.slice(0, 127),
          amount: { currency_code: req.amount.currency, value: toMajorString(req.amount) },
          ...(req.payee.email ? { payee: { email_address: req.payee.email } } : {}),
        },
      ],
      payment_source: { paypal: { vault_id: this.cfg.vaultId } },
    });
    const auth = order?.purchase_units?.[0]?.payments?.authorizations?.[0];
    if (!auth?.id) throw new Error(`PayPal did not return an authorization (status ${order?.status})`);
    return { orderId: order.id, authorizationId: auth.id, expiresAt: auth.expiration_time };
  }

  async capture(authorizationId: string, requestId: string): Promise<{ captureId: string }> {
    const cap = await this.call(`/v2/payments/authorizations/${authorizationId}/capture`, 'POST', requestId, {
      final_capture: true,
    });
    return { captureId: cap.id };
  }

  async void(authorizationId: string): Promise<void> {
    await this.call(`/v2/payments/authorizations/${authorizationId}/void`, 'POST', `void-${authorizationId}`);
  }

  async status(authorizationId: string): Promise<ProviderStatus> {
    const a = await this.call(`/v2/payments/authorizations/${authorizationId}`, 'GET', `get-${authorizationId}`);
    switch (a.status) {
      case 'CREATED':
      case 'PENDING':
        return 'held';
      case 'CAPTURED':
      case 'PARTIALLY_CAPTURED':
        return 'captured';
      case 'VOIDED':
      case 'EXPIRED':
        return 'voided';
      default:
        return 'unknown';
    }
  }
}
