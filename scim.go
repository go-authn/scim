// Package scim is the service-provider half of SCIM 2.0: an HTTP handler
// for Users and Groups (RFC 7644) over a Backend the caller writes, with the
// core schemas (RFC 7643), the filter language, PATCH, paging and the
// discovery endpoints.
//
//	h := &scim.Server{Backend: scim.NewMemory(), BaseURL: "https://app.example.org/scim/v2"}
//	mux.Handle("/scim/v2/", http.StripPrefix("/scim/v2", scim.BearerAuth(token, h)))
//
// An identity provider (Entra ID, Okta, Keycloak, authn-bridge…) is the
// client: it creates, updates and deletes people and groups here, and the
// application reads them from its Backend.
//
// What this package refuses, because each is input from outside:
//
//   - a filter longer than MaxFilterBytes, nested deeper than 32, or with an
//     operator the attribute cannot take (400 invalidFilter);
//   - a body larger than MaxBodyBytes, a PATCH with more than MaxOperations
//     operations (413), a page larger than MaxResults (clamped);
//   - writes to read-only attributes (id, meta, a user's groups: 400
//     mutability) and resources without their core schema;
//   - a PATCH that does not apply in full: PATCH is atomic (RFC 7644
//     §3.5.2), and a concurrent change is detected through the resource
//     version, not overwritten.
//
// Errors from the Backend that are not this package's sentinels become a
// 500 whose body says nothing about them.
package scim

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Schema and message URNs (RFC 7643 §8.7, RFC 7644 §3).
const (
	UserSchema     = "urn:ietf:params:scim:schemas:core:2.0:User"
	GroupSchema    = "urn:ietf:params:scim:schemas:core:2.0:Group"
	ListResponse   = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
	ErrorSchema    = "urn:ietf:params:scim:api:messages:2.0:Error"
	PatchOpSchema  = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
	SPConfigSchema = "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"
	ResourceTypeSc = "urn:ietf:params:scim:schemas:core:2.0:ResourceType"
	SchemaSchema   = "urn:ietf:params:scim:schemas:core:2.0:Schema"
	// MediaType is the SCIM content type (RFC 7644 §8.1).
	MediaType = "application/scim+json"
)

// Meta is the provider-assigned metadata of a resource (RFC 7643 §3.1).
type Meta struct {
	ResourceType string    `json:"resourceType"`
	Created      time.Time `json:"created"`
	LastModified time.Time `json:"lastModified"`
	Location     string    `json:"location,omitempty"`
	// Version is a weak ETag, W/"…", computed by the Server.
	Version string `json:"version,omitempty"`
}

// Name is a user's name (RFC 7643 §4.1.1).
type Name struct {
	Formatted       string `json:"formatted,omitempty"`
	FamilyName      string `json:"familyName,omitempty"`
	GivenName       string `json:"givenName,omitempty"`
	MiddleName      string `json:"middleName,omitempty"`
	HonorificPrefix string `json:"honorificPrefix,omitempty"`
	HonorificSuffix string `json:"honorificSuffix,omitempty"`
}

// Email is one of a user's addresses (RFC 7643 §4.1.2).
type Email struct {
	Value   string `json:"value"`
	Type    string `json:"type,omitempty"`
	Display string `json:"display,omitempty"`
	Primary bool   `json:"primary,omitempty"`
}

// Ref points at another resource: a group a user belongs to, or a member
// of a group.
type Ref struct {
	Value   string `json:"value"`
	Ref     string `json:"$ref,omitempty"`
	Display string `json:"display,omitempty"`
	// Type is "User" or "Group" for a member, "direct" or "indirect" for a
	// user's group.
	Type string `json:"type,omitempty"`
}

// Bool is a boolean that also reads the strings "true" and "false" in any
// case, as some identity providers send them (Entra ID sends "False").
type Bool bool

// UnmarshalJSON reads true, false, "true" or "false".
func (b *Bool) UnmarshalJSON(data []byte) error {
	var v bool
	if err := json.Unmarshal(data, &v); err == nil {
		*b = Bool(v)
		return nil
	}
	var s string
	if err := json.Unmarshal(data, &s); err == nil {
		switch strings.ToLower(s) {
		case "true":
			*b = true
			return nil
		case "false":
			*b = false
			return nil
		}
	}
	return errors.New("want a boolean")
}

// User is a core User (RFC 7643 §4.1). Attributes this package does not
// model are ignored on input.
type User struct {
	Schemas     []string `json:"schemas"`
	ID          string   `json:"id"`
	ExternalID  string   `json:"externalId,omitempty"`
	UserName    string   `json:"userName"`
	Name        *Name    `json:"name,omitempty"`
	DisplayName string   `json:"displayName,omitempty"`
	// Active is nil when the client never said; Enabled treats that as true.
	Active *Bool   `json:"active,omitempty"`
	Emails []Email `json:"emails,omitempty"`
	// Groups is read-only: the Backend fills it from group memberships.
	Groups []Ref `json:"groups,omitempty"`
	Meta   Meta  `json:"meta"`
}

// Enabled reports whether the user is active (absent counts as active).
func (u User) Enabled() bool { return u.Active == nil || bool(*u.Active) }

// Group is a core Group (RFC 7643 §4.2).
type Group struct {
	Schemas     []string `json:"schemas"`
	ID          string   `json:"id"`
	ExternalID  string   `json:"externalId,omitempty"`
	DisplayName string   `json:"displayName"`
	Members     []Ref    `json:"members,omitempty"`
	Meta        Meta     `json:"meta"`
}

// Sentinel errors a Backend returns.
var (
	// ErrNotFound: no resource with that id (404).
	ErrNotFound = errors.New("scim: not found")
	// ErrConflict: a unique attribute (userName, a group's displayName if
	// the backend wants it unique) is taken (409 uniqueness).
	ErrConflict = errors.New("scim: uniqueness conflict")
	// ErrPrecondition: the resource changed since it was read (412).
	ErrPrecondition = errors.New("scim: resource changed")
)

// InvalidValue is a Backend's refusal of a value, such as a member that does
// not exist (400 invalidValue). Its message is shown to the client.
type InvalidValue string

func (e InvalidValue) Error() string { return string(e) }

// Error is a SCIM error response (RFC 7644 §3.12).
type Error struct {
	Status   int
	ScimType string
	Detail   string
}

func (e *Error) Error() string {
	if e.ScimType != "" {
		return fmt.Sprintf("scim: %d %s: %s", e.Status, e.ScimType, e.Detail)
	}
	return fmt.Sprintf("scim: %d: %s", e.Status, e.Detail)
}

// MarshalJSON writes the Error message, status as a string.
func (e *Error) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Schemas  []string `json:"schemas"`
		Status   string   `json:"status"`
		ScimType string   `json:"scimType,omitempty"`
		Detail   string   `json:"detail,omitempty"`
	}{[]string{ErrorSchema}, fmt.Sprint(e.Status), e.ScimType, e.Detail})
}

func badRequest(scimType, format string, a ...any) *Error {
	return &Error{Status: 400, ScimType: scimType, Detail: fmt.Sprintf(format, a...)}
}
