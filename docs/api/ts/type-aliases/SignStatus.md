[**@cleverbase/frontend-helper**](../README.md)

***

[@cleverbase/frontend-helper](../README.md) / SignStatus

# Type Alias: SignStatus

> **SignStatus** = `"pending"` \| `"authorizing"` \| `"completed"` \| `"declined"` \| `"failed"`

Defined in: [index.ts:19](https://github.com/alkem-io/cleverbase-sdk/blob/main/frontend/helper-ts/src/index.ts#L19)

Terminal or in-progress status of a signing session, as reported by the integrator's backend.

- `pending` — session created, signer has not yet authorized.
- `authorizing` — signer is in an authorization redirect (service- or credential-scope step).
- `completed` — the signature was produced.
- `declined` — the signer declined (e.g. OAuth `access_denied`).
- `failed` — the session failed for any other reason.
