# Contract: Thin TypeScript Frontend Helper

A small browser/edge helper (pure TypeScript — no WASM, no crypto) that orchestrates the signer
through the authorization redirect and reflects status. **It performs no cryptography and handles no secrets**
(Principle IV); all signing happens on the integrator's backend via the SDK.

## Responsibilities

- Begin a signing flow by calling the integrator's **own backend** endpoint (which uses the backend
  SDK) and receiving a `RedirectEffect` URL (never a secret, never the session handle).
- Navigate the signer to the authorization URL (same-device redirect) or render the
  Cleverbase-hosted QR/deep-link page (cross-device); both are driven by the returned URL.
- Detect the return to the integrator's `redirect_uri` and hand the `code`+`state` back to the
  backend to finalize — or, when the return carries an OAuth `error` (e.g. `access_denied` on
  decline) instead of a code, hand the `error`+`state` back.
- Poll/subscribe to a backend status endpoint and expose progress to the UI.

## Logical interface

```ts
const helper = new SigningHelper({ startUrl, completeUrl, statusUrl }); // backend endpoints
const { redirectUrl, correlationId } = await helper.start(payload);     // POSTs to startUrl
helper.goToAuthorization(redirectUrl);                                  // sends the browser to authorize
// after the browser returns to redirect_uri, EITHER (success path):
let status = await helper.complete(code, state);                       // forwards to backend; no crypto
// OR, when the redirect returned ?error=access_denied&state=… (signer declined):
status = await helper.reportRedirectError(error, state);               // forwards the error to backend
// poll for status updates: "pending" | "authorizing" | "completed" | "declined" | "failed"
status = await helper.pollStatus(correlationId);
```

The backend `completeUrl` thus receives either `{ code, state }` or `{ error, state }`; the
integrator disambiguates by which field is present.

## Hard constraints (testable)

- The helper MUST NOT receive or transmit `client_secret`, SAD, access tokens, private keys, or the
  `SigningSessionHandle`. (Verified by inspecting outbound traffic — SC-005, US3 acceptance #2.)
- The helper MUST NOT perform signing, hashing of documents, or certificate verification.
- All cryptographic state stays server-side; the helper only carries opaque correlation ids,
  redirect URLs, and the OAuth `code`/`state`.
