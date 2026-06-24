[**@cleverbase/frontend-helper**](../README.md)

***

[@cleverbase/frontend-helper](../README.md) / SigningHelperOptions

# Interface: SigningHelperOptions

Defined in: [index.ts:39](https://github.com/alkem-io/cleverbase-sdk/blob/main/frontend/helper-ts/src/index.ts#L39)

Configuration for a [SigningHelper](../classes/SigningHelper.md): the integrator's backend endpoints plus injectable browser primitives.

## Properties

### completeUrl

> **completeUrl**: `string`

Defined in: [index.ts:47](https://github.com/alkem-io/cleverbase-sdk/blob/main/frontend/helper-ts/src/index.ts#L47)

Backend endpoint hit on redirect return. Receives `{ code, state }` on success
(`complete`) and `{ error, state }` on a signer decline / OAuth error
(`reportRedirectError`); the backend distinguishes by which field is present.

***

### fetchImpl?

> `optional` **fetchImpl?**: (`input`, `init?`) => `Promise`\<`Response`\>

Defined in: [index.ts:51](https://github.com/alkem-io/cleverbase-sdk/blob/main/frontend/helper-ts/src/index.ts#L51)

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

Defined in: [index.ts:53](https://github.com/alkem-io/cleverbase-sdk/blob/main/frontend/helper-ts/src/index.ts#L53)

Injectable navigation (defaults to `location.assign`).

#### Parameters

##### url

`string`

#### Returns

`void`

***

### startUrl

> **startUrl**: `string`

Defined in: [index.ts:41](https://github.com/alkem-io/cleverbase-sdk/blob/main/frontend/helper-ts/src/index.ts#L41)

Backend endpoint that starts a signing session and returns `{ redirectUrl, correlationId }`.

***

### statusUrl

> **statusUrl**: `string`

Defined in: [index.ts:49](https://github.com/alkem-io/cleverbase-sdk/blob/main/frontend/helper-ts/src/index.ts#L49)

Backend endpoint that reports `{ status }` for a `correlationId`.
