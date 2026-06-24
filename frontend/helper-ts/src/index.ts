/**
 * Thin Cleverbase signing frontend helper.
 *
 * Orchestrates the signer through the authorization redirect and reflects status by talking to the
 * integrator's OWN backend (which uses the backend SDK). It performs NO cryptography and handles NO
 * secrets, tokens, session handles, or private keys (Constitution Principle IV). The only data it
 * carries are opaque correlation ids, redirect URLs, and the OAuth `code`/`state`.
 */

/**
 * Terminal or in-progress status of a signing session, as reported by the integrator's backend.
 *
 * - `pending` — session created, signer has not yet authorized.
 * - `authorizing` — signer is in an authorization redirect (service- or credential-scope step).
 * - `completed` — the signature was produced.
 * - `declined` — the signer declined (e.g. OAuth `access_denied`).
 * - `failed` — the session failed for any other reason.
 */
export type SignStatus = "pending" | "authorizing" | "completed" | "declined" | "failed";

/**
 * The allowed {@link SignStatus} values, as a runtime set. This is the single source of truth used
 * both for the type union above and for validating a backend response at runtime ({@link
 * toCompleteResult}), so a malformed status cannot leak through the closed union.
 */
const SIGN_STATUSES: readonly SignStatus[] = [
  "pending",
  "authorizing",
  "completed",
  "declined",
  "failed",
];

function isSignStatus(value: unknown): value is SignStatus {
  return typeof value === "string" && (SIGN_STATUSES as readonly string[]).includes(value);
}

/** Configuration for a {@link SigningHelper}: the integrator's backend endpoints plus injectable browser primitives. */
export interface SigningHelperOptions {
  /** Backend endpoint that starts a signing session and returns `{ redirectUrl, correlationId }`. */
  startUrl: string;
  /**
   * Backend endpoint hit on redirect return. Receives `{ code, state }` on success
   * (`complete`) and `{ error, state }` on a signer decline / OAuth error
   * (`reportRedirectError`); the backend distinguishes by which field is present.
   */
  completeUrl: string;
  /** Backend endpoint that reports `{ status }` for a `correlationId`. */
  statusUrl: string;
  /** Injectable fetch (defaults to the global `fetch`). */
  fetchImpl?: typeof fetch;
  /** Injectable navigation (defaults to `location.assign`). */
  navigate?: (url: string) => void;
}

/** Result of {@link SigningHelper.start}: where to send the signer next, plus the session id to poll. */
export interface StartResult {
  /** Authorization URL the signer's browser must be sent to (drive it with `goToAuthorization`). */
  redirectUrl: string;
  /** Opaque id for this signing session, used to poll status via {@link SigningHelper.pollStatus}. */
  correlationId: string;
}

/**
 * Result of `complete`/`reportRedirectError`. When `redirectUrl` is present the signer must be sent
 * to a SECOND authorization redirect (the credential-scope / SCAL2 step) before the signature can
 * complete; the frontend drives it with `goToAuthorization(result.redirectUrl)`.
 */
export interface CompleteResult {
  /** Current status of the signing session after the redirect return was processed. */
  status: SignStatus;
  /**
   * When present, a SECOND authorization redirect (credential-scope / SCAL2 step) is required;
   * drive it with `goToAuthorization(redirectUrl)`. Absent once no further redirect is needed.
   */
  redirectUrl?: string;
}

/**
 * Drives a Cleverbase signing session from the browser by talking only to the integrator's own
 * backend. It performs no cryptography and handles no secrets, tokens, session handles, or private
 * keys — it carries only opaque correlation ids, redirect URLs, and the OAuth `code`/`state`.
 */
export class SigningHelper {
  private readonly fetchImpl: typeof fetch;
  private readonly navigate: (url: string) => void;

  /**
   * Create a helper bound to the integrator's backend endpoints.
   *
   * @param opts - Backend endpoints plus optional injectable `fetch`/navigation primitives.
   */
  constructor(private readonly opts: SigningHelperOptions) {
    // Resolve global fetch lazily: a caller that only uses goToAuthorization/navigate must not be
    // forced to have a global fetch at construction time (Node <18, some SSR/test runtimes).
    this.fetchImpl =
      opts.fetchImpl ??
      ((input: RequestInfo | URL, init?: RequestInit) => {
        // The DOM lib types `globalThis.fetch` as always present, but at runtime it can be absent
        // (Node <18, some SSR/test runtimes). Read it through a type that admits `undefined` so the
        // runtime guard below is genuine rather than flagged as a dead branch.
        const f = (globalThis as { fetch?: typeof fetch }).fetch;
        if (!f) throw new Error("no global fetch available; pass opts.fetchImpl");
        return f(input, init);
      });
    this.navigate =
      opts.navigate ??
      ((url: string) => {
        (globalThis as unknown as { location: { assign: (u: string) => void } }).location.assign(
          url,
        );
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

  /**
   * Finalize after the redirect returns with `code`+`state` (forwarded to the backend). Returns the
   * current `{ status, redirectUrl? }`: a non-empty `redirectUrl` means a second authorization
   * redirect is required (drive it with `goToAuthorization`).
   */
  async complete(code: string, state: string): Promise<CompleteResult> {
    const res = await this.fetchImpl(this.opts.completeUrl, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ code, state }),
    });
    if (!res.ok) throw new Error(`complete failed: ${res.status}`);
    return toCompleteResult((await res.json()) as CompleteResult);
  }

  /**
   * Forward an OAuth error returned to the `redirect_uri` instead of a code (e.g. `access_denied`
   * when the signer declines) to the backend, which resolves the session to a terminal outcome.
   */
  async reportRedirectError(error: string, state: string): Promise<CompleteResult> {
    const res = await this.fetchImpl(this.opts.completeUrl, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ error, state }),
    });
    if (!res.ok) throw new Error(`reportRedirectError failed: ${res.status}`);
    return toCompleteResult((await res.json()) as CompleteResult);
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

/**
 * Normalize a backend complete/error response into a CompleteResult, omitting `redirectUrl` entirely
 * when absent (so the shape is exact under `exactOptionalPropertyTypes`).
 *
 * Presence — not truthiness — decides whether a second redirect is required: a field that is absent
 * (`undefined`) legitimately means "no further redirect". A present-but-empty `redirectUrl` is a
 * malformed backend response (the contract is a non-empty authorization URL), so we surface it as an
 * error rather than silently dropping it and treating the session as needing no redirect.
 *
 * `status` is likewise validated against the closed {@link SignStatus} union: `res.json()` is
 * untyped at runtime, so a malformed value (e.g. `"complete"` instead of `"completed"`) would
 * otherwise leak through the documented union. We reject it the same way as a malformed redirectUrl.
 */
function toCompleteResult(data: CompleteResult): CompleteResult {
  if (!isSignStatus(data.status)) {
    throw new Error("malformed backend response: status is not a recognized SignStatus value");
  }
  if (data.redirectUrl === undefined) return { status: data.status };
  if (typeof data.redirectUrl !== "string" || data.redirectUrl === "") {
    throw new Error("malformed backend response: redirectUrl present but not a non-empty string");
  }
  return { status: data.status, redirectUrl: data.redirectUrl };
}
