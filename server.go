package scim

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
)

// Server is the SCIM HTTP handler. Mount it at the SCIM root (strip the
// prefix): it serves /Users, /Groups, their /.search, /ServiceProviderConfig,
// /ResourceTypes and /Schemas. It does no authentication: wrap it, for
// instance with BearerAuth.
type Server struct {
	Backend Backend
	// BaseURL is the absolute URL of the SCIM root as clients see it, used
	// for meta.location and Location; empty gives relative locations.
	BaseURL string
	// MaxResults bounds a page (default 100); a larger count is clamped.
	MaxResults int
	// MaxBodyBytes bounds a request body (default 1 MiB).
	MaxBodyBytes int64
	// MaxOperations bounds the operations of one PATCH (default 100).
	MaxOperations int
	// MaxMembers bounds the members of one group (default 10000).
	MaxMembers int
	// Now and NewID replace the clock and the id generator (tests).
	Now   func() time.Time
	NewID func() string
	// ErrorLog receives the Backend errors that become a 500.
	ErrorLog func(err error)
}

func (s *Server) maxResults() int    { return orDefault(s.MaxResults, 100) }
func (s *Server) maxOperations() int { return orDefault(s.MaxOperations, 100) }
func (s *Server) maxMembers() int    { return orDefault(s.MaxMembers, 10_000) }

func (s *Server) maxBody() int64 {
	if s.MaxBodyBytes > 0 {
		return s.MaxBodyBytes
	}
	return 1 << 20
}

func orDefault(v, d int) int {
	if v > 0 {
		return v
	}
	return d
}

func (s *Server) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}

// newID is a random UUID (RFC 9562 version 4).
func (s *Server) newID() string {
	if s.NewID != nil {
		return s.NewID()
	}
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	h := hex.EncodeToString(b[:])
	return h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}

// BearerAuth admits requests carrying "Authorization: Bearer <token>",
// compared in constant time, and answers others 401 with a SCIM error. An
// empty token admits nobody. The token should be long and random (RFC 7644
// §7.4); TLS is the caller's to provide (§7.1).
func BearerAuth(token string, next http.Handler) http.Handler {
	want := sha256.Sum256([]byte("Bearer " + token))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got := sha256.Sum256([]byte(r.Header.Get("Authorization")))
		if token == "" || subtle.ConstantTimeCompare(got[:], want[:]) != 1 {
			w.Header().Set("WWW-Authenticate", `Bearer realm="scim"`)
			writeError(w, &Error{Status: http.StatusUnauthorized, Detail: "a valid bearer token is required"})
			return
		}
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", MediaType)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, e *Error) { writeJSON(w, e.Status, e) }

// fail maps an error to a response; unknown errors are logged, not shown.
func (s *Server) fail(w http.ResponseWriter, err error) {
	var se *Error
	var iv InvalidValue
	switch {
	case errors.As(err, &se):
		writeError(w, se)
	case errors.As(err, &iv):
		writeError(w, badRequest("invalidValue", "%s", string(iv)))
	case errors.Is(err, ErrNotFound):
		writeError(w, &Error{Status: http.StatusNotFound, Detail: "resource not found"})
	case errors.Is(err, ErrConflict):
		writeError(w, &Error{Status: http.StatusConflict, ScimType: "uniqueness", Detail: "a unique attribute is already in use"})
	case errors.Is(err, ErrPrecondition):
		writeError(w, &Error{Status: http.StatusPreconditionFailed, Detail: "the resource changed; read it again"})
	default:
		if s.ErrorLog != nil {
			s.ErrorLog(err)
		}
		writeError(w, &Error{Status: http.StatusInternalServerError, Detail: "internal error"})
	}
}

// ServeHTTP routes a request.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	segs := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(segs) > 2 {
		writeError(w, &Error{Status: http.StatusNotFound, Detail: "no such endpoint"})
		return
	}
	var id string
	if len(segs) == 2 {
		id = segs[1]
	}
	switch segs[0] {
	case "Users", "Groups":
		rt := resourceUser
		if segs[0] == "Groups" {
			rt = resourceGroup
		}
		switch {
		case id == "" && r.Method == http.MethodGet:
			s.list(w, r, rt, r.URL.Query())
		case id == "" && r.Method == http.MethodPost:
			s.create(w, r, rt)
		case id == ".search" && r.Method == http.MethodPost:
			s.search(w, r, rt)
		case id != "" && id != ".search" && r.Method == http.MethodGet:
			s.get(w, r, rt, id)
		case id != "" && id != ".search" && r.Method == http.MethodPut:
			s.replace(w, r, rt, id)
		case id != "" && id != ".search" && r.Method == http.MethodPatch:
			s.patch(w, r, rt, id)
		case id != "" && id != ".search" && r.Method == http.MethodDelete:
			s.delete(w, r, rt, id)
		default:
			writeError(w, &Error{Status: http.StatusMethodNotAllowed, Detail: "method not allowed"})
		}
	case "ServiceProviderConfig", "ResourceTypes", "Schemas":
		if r.Method != http.MethodGet {
			writeError(w, &Error{Status: http.StatusMethodNotAllowed, Detail: "method not allowed"})
			return
		}
		if r.URL.Query().Has("filter") {
			// RFC 7644 §4: so that a client does not believe it filtered.
			writeError(w, &Error{Status: http.StatusForbidden, Detail: "filtering is not supported here"})
			return
		}
		s.discovery(w, segs[0], id)
	default:
		writeError(w, &Error{Status: http.StatusNotFound, Detail: "no such endpoint"})
	}
}

type resourceType int

const (
	resourceUser resourceType = iota
	resourceGroup
)

func (rt resourceType) name() string {
	if rt == resourceUser {
		return "User"
	}
	return "Group"
}

func (rt resourceType) schema() string {
	if rt == resourceUser {
		return UserSchema
	}
	return GroupSchema
}

func (rt resourceType) endpoint() string { return "/" + rt.name() + "s" }

func (s *Server) body(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	b, err := io.ReadAll(io.LimitReader(r.Body, s.maxBody()+1))
	if err != nil {
		writeError(w, badRequest("invalidSyntax", "unreadable body"))
		return nil, false
	}
	if int64(len(b)) > s.maxBody() {
		writeError(w, &Error{Status: http.StatusRequestEntityTooLarge, Detail: fmt.Sprintf("maxPayloadSize is %d bytes", s.maxBody())})
		return nil, false
	}
	return b, true
}

// resource is a User or a Group, as stored.
type resource interface {
	meta() *Meta
}

func (u *User) meta() *Meta  { return &u.Meta }
func (g *Group) meta() *Meta { return &g.Meta }

// decode reads a User or Group body and checks its schema and values.
func (s *Server) decode(b []byte, rt resourceType) (resource, *Error) {
	var probe struct {
		Schemas []string `json:"schemas"`
	}
	if err := json.Unmarshal(b, &probe); err != nil {
		return nil, badRequest("invalidSyntax", "the body is not a JSON object")
	}
	if !slices.ContainsFunc(probe.Schemas, func(x string) bool { return strings.EqualFold(x, rt.schema()) }) {
		return nil, badRequest("invalidSyntax", "schemas must include %s", rt.schema())
	}
	if rt == resourceUser {
		var u User
		if err := json.Unmarshal(b, &u); err != nil {
			return nil, badRequest("invalidValue", "invalid %s: %v", rt.name(), jsonDetail(err))
		}
		if e := s.validUser(&u); e != nil {
			return nil, e
		}
		return &u, nil
	}
	var g Group
	if err := json.Unmarshal(b, &g); err != nil {
		return nil, badRequest("invalidValue", "invalid %s: %v", rt.name(), jsonDetail(err))
	}
	if e := s.validGroup(&g); e != nil {
		return nil, e
	}
	return &g, nil
}

// jsonDetail says what was wrong without echoing the input.
func jsonDetail(err error) string {
	var te *json.UnmarshalTypeError
	if errors.As(err, &te) {
		return "attribute " + te.Field + " has the wrong type"
	}
	return "malformed JSON"
}

const maxString = 1024

func validString(v string) bool {
	if len(v) > maxString {
		return false
	}
	for _, r := range v {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

func (s *Server) validUser(u *User) *Error {
	u.Schemas = []string{UserSchema}
	u.Groups = nil // read-only (RFC 7643 §4.1.2)
	if strings.TrimSpace(u.UserName) == "" || len(u.UserName) > 256 || !validString(u.UserName) {
		return badRequest("invalidValue", "userName is required, at most 256 bytes, without control characters")
	}
	if !validString(u.ExternalID) || !validString(u.DisplayName) || len(u.Emails) > 100 {
		return badRequest("invalidValue", "a value is too long, has control characters, or there are too many emails")
	}
	if u.Name != nil {
		for _, v := range []string{u.Name.Formatted, u.Name.FamilyName, u.Name.GivenName, u.Name.MiddleName, u.Name.HonorificPrefix, u.Name.HonorificSuffix} {
			if !validString(v) {
				return badRequest("invalidValue", "a name is too long or has control characters")
			}
		}
	}
	primaries := 0
	for _, e := range u.Emails {
		if !validString(e.Value) || !validString(e.Type) || !validString(e.Display) {
			return badRequest("invalidValue", "an email is too long or has control characters")
		}
		if e.Primary {
			primaries++
		}
	}
	if primaries > 1 {
		return badRequest("invalidValue", "at most one email may be primary")
	}
	return nil
}

func (s *Server) validGroup(g *Group) *Error {
	g.Schemas = []string{GroupSchema}
	if strings.TrimSpace(g.DisplayName) == "" || !validString(g.DisplayName) || !validString(g.ExternalID) {
		return badRequest("invalidValue", "displayName is required, at most 1024 bytes, without control characters")
	}
	if len(g.Members) > s.maxMembers() {
		return badRequest("invalidValue", "more than %d members", s.maxMembers())
	}
	seen := make(map[string]bool, len(g.Members))
	kept := g.Members[:0]
	for _, m := range g.Members {
		if m.Value == "" || !validString(m.Value) || !validString(m.Display) {
			return badRequest("invalidValue", "a member needs a value")
		}
		if !seen[m.Value] {
			seen[m.Value] = true
			kept = append(kept, Ref{Value: m.Value, Display: m.Display})
		}
	}
	g.Members = kept
	return nil
}

// stamp sets id, meta and the version of a resource about to be stored.
func (s *Server) stamp(res resource, rt resourceType, id string, created time.Time) {
	now := s.now()
	m := res.meta()
	switch r := res.(type) {
	case *User:
		r.ID = id
	case *Group:
		r.ID = id
	}
	if created.IsZero() {
		created = now
	}
	*m = Meta{ResourceType: rt.name(), Created: created, LastModified: now, Location: s.BaseURL + rt.endpoint() + "/" + id}
	m.Version = version(res)
}

// version is a weak ETag over the resource's content.
func version(res resource) string {
	m := res.meta()
	saved := m.Version
	m.Version = ""
	b, _ := json.Marshal(res)
	m.Version = saved
	sum := sha256.Sum256(b)
	return `W/"` + hex.EncodeToString(sum[:12]) + `"`
}

func (s *Server) load(ctx context.Context, rt resourceType, id string) (resource, error) {
	if rt == resourceUser {
		u, err := s.Backend.GetUser(ctx, id)
		return &u, err
	}
	g, err := s.Backend.GetGroup(ctx, id)
	return &g, err
}

// ifMatch checks If-Match against the current version (RFC 7644 §3.14).
func ifMatch(r *http.Request, current string) bool {
	h := r.Header.Get("If-Match")
	if h == "" || h == "*" {
		return true
	}
	for _, v := range strings.Split(h, ",") {
		if strings.TrimSpace(v) == current {
			return true
		}
	}
	return false
}

func (s *Server) respond(w http.ResponseWriter, status int, res resource) {
	w.Header().Set("ETag", res.meta().Version)
	if status == http.StatusCreated {
		w.Header().Set("Location", res.meta().Location)
	}
	writeJSON(w, status, res)
}

func (s *Server) create(w http.ResponseWriter, r *http.Request, rt resourceType) {
	b, ok := s.body(w, r)
	if !ok {
		return
	}
	res, e := s.decode(b, rt)
	if e != nil {
		writeError(w, e)
		return
	}
	s.stamp(res, rt, s.newID(), time.Time{})
	var err error
	if rt == resourceUser {
		err = s.Backend.CreateUser(r.Context(), *res.(*User))
	} else {
		err = s.Backend.CreateGroup(r.Context(), *res.(*Group))
	}
	if err != nil {
		s.fail(w, err)
		return
	}
	stored, err := s.load(r.Context(), rt, res.(interface{ ident() string }).ident())
	if err != nil {
		s.fail(w, err)
		return
	}
	s.respond(w, http.StatusCreated, stored)
}

func (u *User) ident() string  { return u.ID }
func (g *Group) ident() string { return g.ID }

func (s *Server) get(w http.ResponseWriter, r *http.Request, rt resourceType, id string) {
	res, err := s.load(r.Context(), rt, id)
	if err != nil {
		s.fail(w, err)
		return
	}
	if inm := r.Header.Get("If-None-Match"); inm != "" && inm == res.meta().Version {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	q := r.URL.Query()
	m, err := toMap(res)
	if err != nil {
		s.fail(w, err)
		return
	}
	w.Header().Set("ETag", res.meta().Version)
	writeJSON(w, http.StatusOK, project(m, q.Get("attributes"), q.Get("excludedAttributes")))
}

func (s *Server) replace(w http.ResponseWriter, r *http.Request, rt resourceType, id string) {
	b, ok := s.body(w, r)
	if !ok {
		return
	}
	res, e := s.decode(b, rt)
	if e != nil {
		writeError(w, e)
		return
	}
	cur, err := s.load(r.Context(), rt, id)
	if err != nil {
		s.fail(w, err)
		return
	}
	s.store(w, r, rt, id, cur, res)
}

// store replaces cur by res, conditionally on cur's version.
func (s *Server) store(w http.ResponseWriter, r *http.Request, rt resourceType, id string, cur, res resource) {
	if !ifMatch(r, cur.meta().Version) {
		s.fail(w, ErrPrecondition)
		return
	}
	s.stamp(res, rt, id, cur.meta().Created)
	var err error
	if rt == resourceUser {
		err = s.Backend.ReplaceUser(r.Context(), *res.(*User), cur.meta().Version)
	} else {
		err = s.Backend.ReplaceGroup(r.Context(), *res.(*Group), cur.meta().Version)
	}
	if err != nil {
		s.fail(w, err)
		return
	}
	stored, err := s.load(r.Context(), rt, id)
	if err != nil {
		s.fail(w, err)
		return
	}
	s.respond(w, http.StatusOK, stored)
}

func (s *Server) patch(w http.ResponseWriter, r *http.Request, rt resourceType, id string) {
	b, ok := s.body(w, r)
	if !ok {
		return
	}
	var req PatchRequest
	if err := json.Unmarshal(b, &req); err != nil {
		writeError(w, badRequest("invalidSyntax", "the body is not a PatchOp message"))
		return
	}
	if !slices.ContainsFunc(req.Schemas, func(x string) bool { return strings.EqualFold(x, PatchOpSchema) }) {
		writeError(w, badRequest("invalidSyntax", "schemas must include %s", PatchOpSchema))
		return
	}
	if len(req.Operations) == 0 {
		writeError(w, badRequest("invalidValue", "no operations"))
		return
	}
	if len(req.Operations) > s.maxOperations() {
		writeError(w, &Error{Status: http.StatusRequestEntityTooLarge, Detail: fmt.Sprintf("maxOperations is %d", s.maxOperations())})
		return
	}
	cur, err := s.load(r.Context(), rt, id)
	if err != nil {
		s.fail(w, err)
		return
	}
	m, err := toMap(cur)
	if err != nil {
		s.fail(w, err)
		return
	}
	readOnly := map[string]bool{"id": true, "meta": true, "schemas": true}
	if rt == resourceUser {
		readOnly["groups"] = true
	}
	if e := applyPatch(m, req.Operations, readOnly); e != nil {
		writeError(w, e)
		return
	}
	patched, err := json.Marshal(m)
	if err != nil {
		s.fail(w, err)
		return
	}
	if int64(len(patched)) > s.maxBody() {
		writeError(w, &Error{Status: http.StatusRequestEntityTooLarge, Detail: "the patched resource is too large"})
		return
	}
	res, e := s.decode(patched, rt)
	if e != nil {
		writeError(w, e)
		return
	}
	s.store(w, r, rt, id, cur, res)
}

func (s *Server) delete(w http.ResponseWriter, r *http.Request, rt resourceType, id string) {
	if r.Header.Get("If-Match") != "" {
		cur, err := s.load(r.Context(), rt, id)
		if err != nil {
			s.fail(w, err)
			return
		}
		if !ifMatch(r, cur.meta().Version) {
			s.fail(w, ErrPrecondition)
			return
		}
	}
	var err error
	if rt == resourceUser {
		err = s.Backend.DeleteUser(r.Context(), id)
	} else {
		err = s.Backend.DeleteGroup(r.Context(), id)
	}
	if err != nil {
		s.fail(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// SearchRequest is the body of POST /.search (RFC 7644 §3.4.3).
type SearchRequest struct {
	Schemas            []string `json:"schemas"`
	Filter             string   `json:"filter,omitempty"`
	StartIndex         *int     `json:"startIndex,omitempty"`
	Count              *int     `json:"count,omitempty"`
	Attributes         []string `json:"attributes,omitempty"`
	ExcludedAttributes []string `json:"excludedAttributes,omitempty"`
}

func (s *Server) search(w http.ResponseWriter, r *http.Request, rt resourceType) {
	b, ok := s.body(w, r)
	if !ok {
		return
	}
	var req SearchRequest
	if err := json.Unmarshal(b, &req); err != nil {
		writeError(w, badRequest("invalidSyntax", "the body is not a SearchRequest"))
		return
	}
	q := map[string][]string{}
	if req.Filter != "" {
		q["filter"] = []string{req.Filter}
	}
	if req.StartIndex != nil {
		q["startIndex"] = []string{strconv.Itoa(*req.StartIndex)}
	}
	if req.Count != nil {
		q["count"] = []string{strconv.Itoa(*req.Count)}
	}
	if len(req.Attributes) > 0 {
		q["attributes"] = []string{strings.Join(req.Attributes, ",")}
	}
	if len(req.ExcludedAttributes) > 0 {
		q["excludedAttributes"] = []string{strings.Join(req.ExcludedAttributes, ",")}
	}
	s.list(w, r, rt, q)
}

type listResponse struct {
	Schemas      []string         `json:"schemas"`
	TotalResults int              `json:"totalResults"`
	StartIndex   int              `json:"startIndex"`
	ItemsPerPage int              `json:"itemsPerPage"`
	Resources    []map[string]any `json:"Resources"`
}

// pageParam reads a paging parameter: absent → def, not an integer → error.
func pageParam(q map[string][]string, name string, def int) (int, *Error) {
	v := ""
	if vs := q[name]; len(vs) > 0 {
		v = vs[0]
	}
	if v == "" {
		return def, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, badRequest("invalidValue", "%s must be an integer", name)
	}
	return n, nil
}

func first(q map[string][]string, name string) string {
	if vs := q[name]; len(vs) > 0 {
		return vs[0]
	}
	return ""
}

func (s *Server) list(w http.ResponseWriter, r *http.Request, rt resourceType, q map[string][]string) {
	var f *Filter
	if src := first(q, "filter"); src != "" {
		var err error
		if f, err = ParseFilter(src); err != nil {
			s.fail(w, err)
			return
		}
	}
	start, e := pageParam(q, "startIndex", 1)
	if e != nil {
		writeError(w, e)
		return
	}
	count, e := pageParam(q, "count", s.maxResults())
	if e != nil {
		writeError(w, e)
		return
	}
	// RFC 7644 §3.4.2.4: below 1 is 1, negative count is 0.
	start = max(start, 1)
	count = min(max(count, 0), s.maxResults())

	var all []resource
	if rt == resourceUser {
		us, err := s.Backend.ListUsers(r.Context(), f)
		if err != nil {
			s.fail(w, err)
			return
		}
		for i := range us {
			all = append(all, &us[i])
		}
	} else {
		gs, err := s.Backend.ListGroups(r.Context(), f)
		if err != nil {
			s.fail(w, err)
			return
		}
		for i := range gs {
			all = append(all, &gs[i])
		}
	}
	// A stable order, so that pages do not overlap.
	slices.SortFunc(all, func(a, b resource) int {
		return strings.Compare(a.(interface{ ident() string }).ident(), b.(interface{ ident() string }).ident())
	})
	var matched []map[string]any
	for _, res := range all {
		m, err := toMap(res)
		if err != nil {
			s.fail(w, err)
			return
		}
		if f == nil || f.Match(m) {
			matched = append(matched, m)
		}
	}
	out := listResponse{Schemas: []string{ListResponse}, TotalResults: len(matched), StartIndex: start, Resources: []map[string]any{}}
	if start <= len(matched) {
		end := min(start-1+count, len(matched))
		for _, m := range matched[start-1 : end] {
			out.Resources = append(out.Resources, project(m, first(q, "attributes"), first(q, "excludedAttributes")))
		}
	}
	out.ItemsPerPage = len(out.Resources)
	writeJSON(w, http.StatusOK, out)
}

func toMap(v any) (map[string]any, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var m map[string]any
	d := json.NewDecoder(bytes.NewReader(b))
	if err := d.Decode(&m); err != nil {
		return nil, err
	}
	return m, nil
}

// project applies attributes / excludedAttributes (RFC 7644 §3.9). id and
// schemas are always returned.
func project(m map[string]any, attributes, excluded string) map[string]any {
	if attributes != "" {
		out := map[string]any{}
		for _, k := range []string{"schemas", "id"} {
			if v, ok := m[k]; ok {
				out[k] = v
			}
		}
		for _, a := range strings.Split(attributes, ",") {
			p, err := parseAttrPath(strings.TrimSpace(a))
			if err != nil {
				continue
			}
			k := key(m, p.attr)
			v, ok := m[k]
			if !ok {
				continue
			}
			if p.sub == "" {
				out[k] = v
				continue
			}
			if sm, isMap := v.(map[string]any); isMap {
				dst, _ := out[k].(map[string]any)
				if dst == nil {
					dst = map[string]any{}
				}
				sk := key(sm, p.sub)
				if sv, ok := sm[sk]; ok {
					dst[sk] = sv
				}
				out[k] = dst
			}
		}
		return out
	}
	if excluded != "" {
		for _, a := range strings.Split(excluded, ",") {
			p, err := parseAttrPath(strings.TrimSpace(a))
			if err != nil || p.attr == "id" || p.attr == "schemas" {
				continue
			}
			k := key(m, p.attr)
			if p.sub == "" {
				delete(m, k)
			} else if sm, ok := m[k].(map[string]any); ok {
				delete(sm, key(sm, p.sub))
			}
		}
	}
	return m
}
