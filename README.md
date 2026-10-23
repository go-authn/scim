# scim

[![Go Reference](https://pkg.go.dev/badge/github.com/go-authn/scim.svg)](https://pkg.go.dev/github.com/go-authn/scim)
[![License](https://img.shields.io/badge/license-BSD--3--Clause-0A6E96?style=flat-square)](LICENSE)
[![CI](https://github.com/go-authn/scim/actions/workflows/ci.yml/badge.svg)](https://github.com/go-authn/scim/actions/workflows/ci.yml)

**SCIM 2.0 provisioning, the service-provider half.** An identity provider
(Entra ID, Okta, Keycloak, …) creates, updates and deletes people and groups
in your application over HTTP; this package is that HTTP endpoint, for Users
and Groups (RFC 7643, RFC 7644), over a `Backend` you write. Pure Go,
`CGO_ENABLED=0`, standard library only.

```go
srv := &scim.Server{
	Backend: scim.NewMemory(),                     // or your database
	BaseURL: "https://app.example.org/scim/v2",    // for meta.location
}
mux.Handle("/scim/v2/", http.StripPrefix("/scim/v2", scim.BearerAuth(token, srv)))
```

## What it serves

| | |
|---|---|
| `/Users`, `/Groups` | `GET` (list: `filter`, `startIndex`, `count`, `attributes`, `excludedAttributes`), `POST` (201 with `Location`) |
| `/Users/{id}`, `/Groups/{id}` | `GET` (`ETag`, `If-None-Match`), `PUT`, `PATCH`, `DELETE` (`If-Match` on all three) |
| `/Users/.search`, `/Groups/.search` | `POST` a SearchRequest, for queries that should not sit in a URL (RFC 7644 §3.4.3, §7.5.2) |
| `/ServiceProviderConfig`, `/ResourceTypes`, `/Schemas` | discovery (RFC 7644 §4); a `filter` there is answered 403 |

- **Filters**: the whole grammar of RFC 7644 §3.4.2.2 — `eq ne co sw ew gt lt
  ge le pr`, `and or not`, parentheses, value filters such as
  `emails[type eq "work" and value co "@example.org"]`, schema-qualified paths,
  extension attributes. Names and operators without case; string values
  without case except where RFC 7643 says `caseExact` (`id`, `externalId`,
  `$ref`, `meta.version`, references' `value`).
- **PATCH**: `add`, `remove`, `replace` with and without a path, value-filter
  paths with a sub-attribute (`emails[type eq "work"].value`), atomic: an
  operation that fails leaves the resource as it was. Concurrent writers are
  detected through the resource version, never overwritten.
- **Paging**: 1-based `startIndex`, `count` clamped to `MaxResults` (RFC 7644
  §3.4.2.4: below 1 is 1, a negative count is 0), in a stable order.
- **What identity providers really send**, tested with their payloads: Entra
  ID's `"Replace"`, its string booleans (`"active": "False"`), its member
  removal by value list, its filtered add that creates an email; Okta's replace
  without a path that repeats the `id`.

## The Backend

```go
type Backend interface {
	CreateUser(ctx, User) error
	GetUser(ctx, id) (User, error)                  // ErrNotFound
	ReplaceUser(ctx, User, ifVersion string) error  // ErrPrecondition when changed
	DeleteUser(ctx, id) error
	ListUsers(ctx, *Filter) ([]User, error)         // may ignore the filter
	// … and the same for Group
}
```

The Server assigns ids, timestamps and versions, validates input and applies
PATCH; the Backend keeps what it is given and enforces what only it can see:
`ErrConflict` for a taken `userName` (409 `uniqueness`), `InvalidValue` for a
member that does not exist (400 `invalidValue`), `ErrPrecondition` when the
stored version is not the one that was read. A list method may narrow by the
filter — `Filter.Equality()` names the cheap case, `userName eq "…"` — or
return everything: the Server applies the filter exactly to what comes back.
`NewMemory()` is the reference implementation.

## What it refuses

Everything here comes from outside, so the limits are part of the API:

| | |
|---|---|
| a body over `MaxBodyBytes` (1 MiB), a PATCH with more than `MaxOperations` (100), or one that grows the resource past the body limit | 413 |
| a group with more than `MaxMembers` (10 000) | 400 `invalidValue` |
| a filter over 4 KiB, nested deeper than 32, with an unknown operator, or `gt` on a boolean | 400 `invalidFilter` |
| writes to `id`, `meta`, `schemas` or a user's `groups` | 400 `mutability` |
| a resource without its core schema, a `userName` that is empty, over 256 bytes or has control characters, two primary emails | 400 |
| a missing or wrong bearer token (`BearerAuth`, constant time; an empty token admits nobody) | 401 |
| any Backend error that is not one of the sentinels | 500 with a body that says nothing; the error goes to `ErrorLog` |

Duplicate members are skipped in linear time, so a PATCH adding ten thousand
members costs ten thousand map lookups rather than a hundred million
comparisons. The filter, PATCH and the whole handler are fuzzed
(`FuzzFilter`, `FuzzPatch`, `FuzzServer`).

**Not supported**: bulk operations, sorting, password changes, `/Me`
(announced as such in `/ServiceProviderConfig`).

## References

[RFC 7643](https://www.rfc-editor.org/rfc/rfc7643) (core schema),
[RFC 7644](https://www.rfc-editor.org/rfc/rfc7644) (protocol): §3.4.2.2 filters,
§3.4.2.4 paging, §3.5.2 PATCH, §3.12 errors, §3.14 versions, §4 discovery, §7
security.

## Licence

BSD-3-Clause.
