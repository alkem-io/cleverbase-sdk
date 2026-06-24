# Changelog

All notable changes to `@cleverbase/frontend-helper` are documented here.

## 0.2.0

### Changed (breaking, pre-1.0)

- `complete()` and `reportRedirectError()` now resolve to `CompleteResult` (`{ status,
  redirectUrl? }`) instead of a bare `SignStatus`. When `redirectUrl` is present, the signer must be
  sent to a **second** authorization redirect (the credential-scope / SCAL2 step) before the
  signature can finish — drive it with `goToAuthorization(result.redirectUrl)`.

  Migration: replace `const status = await helper.complete(...)` with
  `const { status, redirectUrl } = await helper.complete(...)` and, if `redirectUrl` is set, call
  `helper.goToAuthorization(redirectUrl)`.

### Added

- `CompleteResult` interface.

## 0.1.0

- Initial release: redirect orchestration + status polling, no cryptography and no secrets.
