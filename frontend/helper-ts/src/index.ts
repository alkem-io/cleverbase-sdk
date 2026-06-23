/**
 * Thin Cleverbase signing frontend helper.
 *
 * Orchestrates the signer through the authorization redirect and reflects status by talking to the
 * integrator's OWN backend (which uses the backend SDK). It performs NO cryptography and handles NO
 * secrets, tokens, session handles, or private keys (Constitution Principle IV). The only data it
 * carries are opaque correlation ids, redirect URLs, and the OAuth `code`/`state`.
 */

export type SignStatus = "pending" | "authorizing" | "completed" | "declined" | "failed";

export interface SigningHelperOptions {
  /** Backend endpoint that starts a signing session and returns `{ redirectUrl, correlationId }`. */
  startUrl: string;
  /** Backend endpoint that finalizes after the redirect return (receives `{ code, state }`). */
  completeUrl: string;
  /** Backend endpoint that reports `{ status }` for a `correlationId`. */
  statusUrl: string;
  /** Injectable fetch (defaults to the global `fetch`). */
  fetchImpl?: typeof fetch;
  /** Injectable navigation (defaults to `location.assign`). */
  navigate?: (url: string) => void;
}

export interface StartResult {
  redirectUrl: string;
  correlationId: string;
}

export class SigningHelper {
  private readonly fetchImpl: typeof fetch;
  private readonly navigate: (url: string) => void;

  constructor(private readonly opts: SigningHelperOptions) {
    // Resolve global fetch lazily: a caller that only uses goToAuthorization/navigate must not be
    // forced to have a global fetch at construction time (Node <18, some SSR/test runtimes).
    this.fetchImpl =
      opts.fetchImpl ??
      ((input: RequestInfo | URL, init?: RequestInit) => {
        const f = globalThis.fetch;
        if (!f) throw new Error("no global fetch available; pass opts.fetchImpl");
        return f(input, init);
      });
    this.navigate =
      opts.navigate ??
      ((url: string) => {
        (globalThis as unknown as { location: { assign: (u: string) => void } }).location.assign(url);
      });
  }

  /** Ask the backend to start a signing session; returns the authorization redirect URL. */
  async start(payload: Record<string, unknown> = {}): Promise<StartResult> {
    const res = await this.fetchImpl(this.opts.startUrl, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(payload),
    });
    if (!res.ok) throw new Error(`start failed: ${res.status}`);
    const data = (await res.json()) as StartResult;
    return { redirectUrl: data.redirectUrl, correlationId: data.correlationId };
  }

  /** Send the signer's browser to the authorization URL (same-device redirect / hosted QR page). */
  goToAuthorization(redirectUrl: string): void {
    this.navigate(redirectUrl);
  }

  /** Finalize after the redirect returns with `code`+`state` (forwarded to the backend). */
  async complete(code: string, state: string): Promise<SignStatus> {
    const res = await this.fetchImpl(this.opts.completeUrl, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ code, state }),
    });
    if (!res.ok) throw new Error(`complete failed: ${res.status}`);
    const data = (await res.json()) as { status: SignStatus };
    return data.status;
  }

  /**
   * Forward an OAuth error returned to the `redirect_uri` instead of a code (e.g. `access_denied`
   * when the signer declines) to the backend, which resolves the session to a terminal outcome.
   */
  async reportRedirectError(error: string, state: string): Promise<SignStatus> {
    const res = await this.fetchImpl(this.opts.completeUrl, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ error, state }),
    });
    if (!res.ok) throw new Error(`reportRedirectError failed: ${res.status}`);
    const data = (await res.json()) as { status: SignStatus };
    return data.status;
  }

  /** Poll the backend for the current status. */
  async pollStatus(correlationId: string): Promise<SignStatus> {
    const url = `${this.opts.statusUrl}?correlationId=${encodeURIComponent(correlationId)}`;
    const res = await this.fetchImpl(url, { method: "GET" });
    if (!res.ok) throw new Error(`status failed: ${res.status}`);
    const data = (await res.json()) as { status: SignStatus };
    return data.status;
  }
}
