[**@cleverbase/frontend-helper**](../README.md)

***

[@cleverbase/frontend-helper](../README.md) / SigningHelper

# Class: SigningHelper

Defined in: [index.ts:84](https://github.com/alkem-io/cleverbase-sdk/blob/main/frontend/helper-ts/src/index.ts#L84)

Drives a Cleverbase signing session from the browser by talking only to the integrator's own
backend. It performs no cryptography and handles no secrets, tokens, session handles, or private
keys — it carries only opaque correlation ids, redirect URLs, and the OAuth `code`/`state`.

## Constructors

### Constructor

> **new SigningHelper**(`opts`): `SigningHelper`

Defined in: [index.ts:93](https://github.com/alkem-io/cleverbase-sdk/blob/main/frontend/helper-ts/src/index.ts#L93)

Create a helper bound to the integrator's backend endpoints.

#### Parameters

##### opts

[`SigningHelperOptions`](../interfaces/SigningHelperOptions.md)

Backend endpoints plus optional injectable `fetch`/navigation primitives.

#### Returns

`SigningHelper`

## Methods

### complete()

> **complete**(`code`, `state`): `Promise`\<[`CompleteResult`](../interfaces/CompleteResult.md)\>

Defined in: [index.ts:137](https://github.com/alkem-io/cleverbase-sdk/blob/main/frontend/helper-ts/src/index.ts#L137)

Finalize after the redirect returns with `code`+`state` (forwarded to the backend). Returns the
current `{ status, redirectUrl? }`: a non-empty `redirectUrl` means a second authorization
redirect is required (drive it with `goToAuthorization`).

#### Parameters

##### code

`string`

##### state

`string`

#### Returns

`Promise`\<[`CompleteResult`](../interfaces/CompleteResult.md)\>

***

### goToAuthorization()

> **goToAuthorization**(`redirectUrl`): `void`

Defined in: [index.ts:128](https://github.com/alkem-io/cleverbase-sdk/blob/main/frontend/helper-ts/src/index.ts#L128)

Send the signer's browser to the authorization URL (same-device redirect / hosted QR page).

#### Parameters

##### redirectUrl

`string`

#### Returns

`void`

***

### pollStatus()

> **pollStatus**(`correlationId`): `Promise`\<[`SignStatus`](../type-aliases/SignStatus.md)\>

Defined in: [index.ts:162](https://github.com/alkem-io/cleverbase-sdk/blob/main/frontend/helper-ts/src/index.ts#L162)

Poll the backend for the current status.

#### Parameters

##### correlationId

`string`

#### Returns

`Promise`\<[`SignStatus`](../type-aliases/SignStatus.md)\>

***

### reportRedirectError()

> **reportRedirectError**(`error`, `state`): `Promise`\<[`CompleteResult`](../interfaces/CompleteResult.md)\>

Defined in: [index.ts:151](https://github.com/alkem-io/cleverbase-sdk/blob/main/frontend/helper-ts/src/index.ts#L151)

Forward an OAuth error returned to the `redirect_uri` instead of a code (e.g. `access_denied`
when the signer declines) to the backend, which resolves the session to a terminal outcome.

#### Parameters

##### error

`string`

##### state

`string`

#### Returns

`Promise`\<[`CompleteResult`](../interfaces/CompleteResult.md)\>

***

### start()

> **start**(`payload?`): `Promise`\<[`StartResult`](../interfaces/StartResult.md)\>

Defined in: [index.ts:116](https://github.com/alkem-io/cleverbase-sdk/blob/main/frontend/helper-ts/src/index.ts#L116)

Ask the backend to start a signing session; returns the authorization redirect URL.

#### Parameters

##### payload?

`Record`\<`string`, `unknown`\> = `{}`

#### Returns

`Promise`\<[`StartResult`](../interfaces/StartResult.md)\>
