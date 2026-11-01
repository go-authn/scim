# Changelog

## v0.2.0

Audit, fuzz, chaos and performance pass.

### Fixed
- A PATCH or PUT without `If-Match` that lost a race with another writer was
  answered 412 although the client asked for no precondition. It is now redone
  on the newer version (at most 32 times); with `If-Match` the answer is still
  412. Twenty-four concurrent PATCHes now all land (nine of them failed before).
- `DELETE` with `If-Match` checked the version and deleted in two steps: a write
  landing between them was deleted unseen. A Backend implementing the new
  `ConditionalDeleter` closes the gap; `Memory` does.
- Removing a member (or any element) through a filter that matches nothing is a
  success, not 400 `noTarget` (RFC 7644 §3.5.2.2).
- A PATCH without a path applied its keys in map order; `name` and
  `name.givenName` in one object gave a different resource from run to run. Keys
  are applied in sorted order.
- `BearerAuth` refused `bearer <token>`; the scheme name is case-insensitive
  (RFC 7235 §2.1).
- `startIndex` or `count` beyond an `int` was a 400 on 32-bit targets and a
  clamped page on 64-bit ones; both clamp.

### Added
- `Server.ReadTimeout` (default 30 s): a request body that takes longer to
  arrive is cut off with a 400, whatever the surrounding `http.Server` does.
- `ConditionalDeleter`, `Memory.DeleteUserIf`, `Memory.DeleteGroupIf`.
- Fuzz targets `FuzzPatchPath` and `FuzzPatchThenDecode`; tests for concurrent
  writers (`-race`), Backend failure atomicity and opacity, the filter worst
  case, filter values as data, and password never returned.

### Performance
- Users and groups become JSON objects directly instead of by marshal and
  decode; a list without a filter builds objects for the page only; `Memory`
  narrows `userName`/`externalId`/`id`/`displayName` equality and computes
  memberships in one pass. 10,000 users, per list request: page 789,417 to
  14,952 allocations; `userName eq` 797,979 to 90; full-scan filter 818,847 to
  361,098.

## v0.1.1
Minimum Go version 1.27.3.

## v0.1.0
First release.
