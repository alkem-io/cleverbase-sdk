[**@cleverbase/frontend-helper**](../README.md)

***

[@cleverbase/frontend-helper](../README.md) / CompleteResult

# Interface: CompleteResult

Defined in: [index.ts:52](https://github.com/alkem-io/cleverbase-sdk/blob/main/frontend/helper-ts/src/index.ts#L52)

Result of `complete`/`reportRedirectError`. When `redirectUrl` is present the signer must be sent
to a SECOND authorization redirect (the credential-scope / SCAL2 step) before the signature can
complete; the frontend drives it with `goToAuthorization(result.redirectUrl)`.

## Properties

### redirectUrl?

> `optional` **redirectUrl?**: `string`

Defined in: [index.ts:59](https://github.com/alkem-io/cleverbase-sdk/blob/main/frontend/helper-ts/src/index.ts#L59)

When present, a SECOND authorization redirect (credential-scope / SCAL2 step) is required;
drive it with `goToAuthorization(redirectUrl)`. Absent once no further redirect is needed.

***

### status

> **status**: [`SignStatus`](../type-aliases/SignStatus.md)

Defined in: [index.ts:54](https://github.com/alkem-io/cleverbase-sdk/blob/main/frontend/helper-ts/src/index.ts#L54)

Current status of the signing session after the redirect return was processed.
