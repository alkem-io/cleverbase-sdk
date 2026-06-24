[**@cleverbase/frontend-helper**](../README.md)

***

[@cleverbase/frontend-helper](../README.md) / SigningHelperOptions

# Interface: SigningHelperOptions

Defined in: [index.ts:22](https://github.com/alkem-io/cleverbase-sdk/blob/main/frontend/helper-ts/src/index.ts#L22)

Configuration for a [SigningHelper](../classes/SigningHelper.md): the integrator's backend endpoints plus injectable browser primitives.

## Properties

### completeUrl

> **completeUrl**: `string`

Defined in: [index.ts:30](https://github.com/alkem-io/cleverbase-sdk/blob/main/frontend/helper-ts/src/index.ts#L30)

Backend endpoint hit on redirect return. Receives `{ code, state }` on success
(`complete`) and `{ error, state }` on a signer decline / OAuth error
(`reportRedirectError`); the backend distinguishes by which field is present.

***

### fetchImpl?

> `optional` **fetchImpl?**: (`input`, `init?`) => `Promise`\<`Response`\>

Defined in: [index.ts:34](https://github.com/alkem-io/cleverbase-sdk/blob/main/frontend/helper-ts/src/index.ts#L34)

Injectable fetch (defaults to the global `fetch`).

[MDN Reference](https://developer.mozilla.org/docs/Web/API/Window/fetch)

#### Parameters

##### input

`RequestInfo` \| `URL`

##### init?

`RequestInit`

#### Returns

`Promise`\<`Response`\>

***

### navigate?

> `optional` **navigate?**: (`url`) => `void`

Defined in: [index.ts:36](https://github.com/alkem-io/cleverbase-sdk/blob/main/frontend/helper-ts/src/index.ts#L36)

Injectable navigation (defaults to `location.assign`).

#### Parameters

##### url

`string`

#### Returns

`void`

***

### startUrl

> **startUrl**: `string`

Defined in: [index.ts:24](https://github.com/alkem-io/cleverbase-sdk/blob/main/frontend/helper-ts/src/index.ts#L24)

Backend endpoint that starts a signing session and returns `{ redirectUrl, correlationId }`.

***

### statusUrl

> **statusUrl**: `string`

Defined in: [index.ts:32](https://github.com/alkem-io/cleverbase-sdk/blob/main/frontend/helper-ts/src/index.ts#L32)

Backend endpoint that reports `{ status }` for a `correlationId`.
