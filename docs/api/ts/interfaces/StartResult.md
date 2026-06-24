[**@cleverbase/frontend-helper**](../README.md)

***

[@cleverbase/frontend-helper](../README.md) / StartResult

# Interface: StartResult

Defined in: [index.ts:57](https://github.com/alkem-io/cleverbase-sdk/blob/main/frontend/helper-ts/src/index.ts#L57)

Result of [SigningHelper.start](../classes/SigningHelper.md#start): where to send the signer next, plus the session id to poll.

## Properties

### correlationId

> **correlationId**: `string`

Defined in: [index.ts:61](https://github.com/alkem-io/cleverbase-sdk/blob/main/frontend/helper-ts/src/index.ts#L61)

Opaque id for this signing session, used to poll status via [SigningHelper.pollStatus](../classes/SigningHelper.md#pollstatus).

***

### redirectUrl

> **redirectUrl**: `string`

Defined in: [index.ts:59](https://github.com/alkem-io/cleverbase-sdk/blob/main/frontend/helper-ts/src/index.ts#L59)

Authorization URL the signer's browser must be sent to (drive it with `goToAuthorization`).
