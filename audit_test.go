package scim

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const userBody = `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"alice"}`

func patchBody(ops string) string {
	return `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":` + ops + `}`
}

// RFC 7644 §3.14: without If-Match the client asked for no precondition, so
// concurrent PATCHes must all succeed and none may be lost. The version check
// against the Backend only guards the read-modify-write, and a writer that
// lost that race is retried, not refused with a 412.
func TestConcurrentPatchWithoutIfMatchLosesNothing(t *testing.T) {
	c, _ := newClient(t)
	c.want(201, "POST", "/Users", userBody)
	const n = 24
	var wg sync.WaitGroup
	var failed atomic.Int32
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			op := fmt.Sprintf(`[{"op":"add","path":"emails","value":[{"value":"a%d@example.org"}]}]`, i)
			if code, m, _ := c.do("PATCH", "/Users/id-001", patchBody(op)); code != 200 {
				failed.Add(1)
				t.Errorf("patch %d: %d %v", i, code, m)
			}
		}()
	}
	wg.Wait()
	got := c.want(200, "GET", "/Users/id-001", "")
	emails, _ := got["emails"].([]any)
	if len(emails) != n || failed.Load() != 0 {
		t.Fatalf("%d emails kept of %d, %d requests failed", len(emails), n, failed.Load())
	}
}

// With If-Match, exactly one of N writers holding the same version wins.
func TestConcurrentPatchWithIfMatchHasOneWinner(t *testing.T) {
	c, _ := newClient(t)
	created := c.want(201, "POST", "/Users", userBody)
	etag := created["meta"].(map[string]any)["version"].(string)
	const n = 16
	var wg sync.WaitGroup
	var ok, stale atomic.Int32
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			op := fmt.Sprintf(`[{"op":"replace","path":"displayName","value":"w%d"}]`, i)
			switch code, _, _ := c.do("PATCH", "/Users/id-001", patchBody(op), "If-Match", etag); code {
			case 200:
				ok.Add(1)
			case 412:
				stale.Add(1)
			default:
				t.Errorf("unexpected %d", code)
			}
		}()
	}
	wg.Wait()
	if ok.Load() != 1 || stale.Load() != n-1 {
		t.Fatalf("%d winners, %d refused; want 1 and %d", ok.Load(), stale.Load(), n-1)
	}
}

// A conditional DELETE is atomic with the version check when the Backend can
// say so; Memory can.
func TestConditionalDeleteIsAtomic(t *testing.T) {
	c, mem := newClient(t)
	created := c.want(201, "POST", "/Users", userBody)
	etag := created["meta"].(map[string]any)["version"].(string)
	c.want(200, "PATCH", "/Users/id-001", patchBody(`[{"op":"replace","path":"displayName","value":"x"}]`))
	c.want(412, "DELETE", "/Users/id-001", "", "If-Match", etag)
	if _, err := mem.GetUser(context.Background(), "id-001"); err != nil {
		t.Fatal("a stale If-Match deleted the user")
	}
	if err := mem.DeleteUserIf(context.Background(), "id-001", etag); err != ErrPrecondition {
		t.Fatalf("DeleteUserIf with a stale version: %v", err)
	}
}

// racyBackend lets a concurrent writer in right after the Server has read a
// user, which is exactly the window between "check If-Match" and "delete".
type racyBackend struct {
	*Memory
	armed atomic.Bool
}

func (b *racyBackend) GetUser(ctx context.Context, id string) (User, error) {
	u, err := b.Memory.GetUser(ctx, id)
	if b.armed.CompareAndSwap(true, false) {
		w := u
		w.DisplayName = "changed by someone else"
		w.Meta.Version = `W/"newer"`
		_ = b.Memory.ReplaceUser(ctx, w, u.Meta.Version)
	}
	return u, err
}

func TestDeleteIfMatchCannotDeleteANewerVersion(t *testing.T) {
	rb := &racyBackend{Memory: NewMemory()}
	srv := &Server{Backend: rb}
	do := func(method, path, body string, hdr ...string) int {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		for i := 0; i+1 < len(hdr); i += 2 {
			r.Header.Set(hdr[i], hdr[i+1])
		}
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, r)
		return w.Code
	}
	if code := do("POST", "/Users", userBody); code != 201 {
		t.Fatal(code)
	}
	us, _ := rb.Memory.ListUsers(context.Background(), nil)
	id, v := us[0].ID, us[0].Meta.Version
	rb.armed.Store(true) // a writer slips in right after the Server reads the user
	if code := do("DELETE", "/Users/"+id, "", "If-Match", v); code != 412 {
		t.Fatalf("DELETE of a version that changed meanwhile: %d, want 412", code)
	}
	if _, err := rb.Memory.GetUser(context.Background(), id); err != nil {
		t.Fatalf("the user is gone: %v", err)
	}
}

// RFC 7644 §3.5.2.2: removing a member that is not there changes nothing and
// succeeds.
func TestRemoveAbsentMemberSucceeds(t *testing.T) {
	c, _ := newClient(t)
	c.want(201, "POST", "/Users", userBody)
	c.want(201, "POST", "/Groups", `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"g"}`)
	c.want(200, "PATCH", "/Groups/id-002", patchBody(`[{"op":"remove","path":"members[value eq \"id-001\"]"}]`))
}

// A PATCH without a path applies its keys in a fixed order, so the same
// request always gives the same resource.
func TestPatchWithoutPathIsDeterministic(t *testing.T) {
	var first string
	for i := 0; i < 50; i++ {
		m := map[string]any{"name": map[string]any{"givenName": "old"}}
		ops := []PatchOp{{Op: "replace", Value: json.RawMessage(`{"name.givenName":"a","name":{"givenName":"b"}}`)}}
		if err := applyPatch(m, ops, map[string]bool{}); err != nil {
			t.Fatal(err)
		}
		b, _ := json.Marshal(m)
		if i == 0 {
			first = string(b)
		} else if string(b) != first {
			t.Fatalf("run %d: %s, first run %s", i, b, first)
		}
	}
}

// RFC 7644 §3.10 / RFC 7643 §3.1: an attribute may be named with the schema
// URN of its resource; that is the same attribute.
func TestSchemaPrefixedPatchPathIsTheCoreAttribute(t *testing.T) {
	c, _ := newClient(t)
	c.want(201, "POST", "/Users", userBody)
	c.want(200, "PATCH", "/Users/id-001", patchBody(`[{"op":"replace","path":"urn:ietf:params:scim:schemas:core:2.0:User:displayName","value":"Al"}]`))
	if got := c.want(200, "GET", "/Users/id-001", ""); got["displayName"] != "Al" {
		t.Fatalf("displayName = %v", got["displayName"])
	}
	c.want(400, "PATCH", "/Users/id-001", patchBody(`[{"op":"replace","path":"urn:ietf:params:scim:schemas:core:2.0:User:id","value":"x"}]`))
}

// RFC 7235 §2.1: the authentication scheme is case-insensitive.
func TestBearerSchemeIsCaseInsensitive(t *testing.T) {
	h := BearerAuth("tok", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	for auth, want := range map[string]int{
		"Bearer tok": 200, "bearer tok": 200, "BEARER tok": 200,
		"Bearer tok ": 401, "Bearer  tok": 401, "Bearer": 401, "": 401, "Basic tok": 401, "Bearer tok2": 401,
	} {
		r := httptest.NewRequest("GET", "/Users", nil)
		if auth != "" {
			r.Header.Set("Authorization", auth)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != want {
			t.Errorf("%q: %d, want %d", auth, w.Code, want)
		}
	}
}

// RFC 7644 §3.4.2.4: a startIndex beyond what an int holds is an empty page,
// not a malformed request, on every word size.
func TestHugePagingValuesAreClamped(t *testing.T) {
	c, _ := newClient(t)
	c.want(201, "POST", "/Users", userBody)
	for _, q := range []string{"startIndex=99999999999999999999", "startIndex=9223372036854775807", "count=99999999999999999999", "startIndex=-99999999999999999999"} {
		got := c.want(200, "GET", "/Users?"+q, "")
		if got["totalResults"] != float64(1) {
			t.Errorf("%s: %v", q, got)
		}
	}
	c.want(400, "GET", "/Users?startIndex=abc", "")
}

// A client that sends its body one byte at a time is cut off by the read
// deadline instead of holding a goroutine and a connection forever.
func TestSlowBodyIsCutOff(t *testing.T) {
	srv := &Server{Backend: NewMemory(), ReadTimeout: 300 * time.Millisecond}
	ts := httptest.NewServer(srv)
	defer ts.Close()
	conn, err := net.Dial("tcp", ts.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_, _ = fmt.Fprintf(conn, "POST /Users HTTP/1.1\r\nHost: x\r\nContent-Type: %s\r\nContent-Length: 1000\r\n\r\n{", MediaType)
	start := time.Now()
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 4096)
	n, _ := conn.Read(buf)
	if took := time.Since(start); took > 3*time.Second || !strings.Contains(string(buf[:n]), "HTTP/1.1 4") {
		t.Fatalf("after %v: %q", took, buf[:n])
	}
}

// failingBackend errors on demand, to see what the client is told.
type failingBackend struct {
	*Memory
	failReplace, failList atomic.Bool
}

func (f *failingBackend) ReplaceUser(ctx context.Context, u User, v string) error {
	if f.failReplace.Load() {
		return fmt.Errorf("disk on fire: secret-dsn=postgres://u:pw@h/db")
	}
	return f.Memory.ReplaceUser(ctx, u, v)
}

func (f *failingBackend) ListUsers(ctx context.Context, fl *Filter) ([]User, error) {
	if f.failList.Load() {
		return nil, fmt.Errorf("ldap bind failed for cn=admin,pw=hunter2")
	}
	return f.Memory.ListUsers(ctx, fl)
}

// A Backend failing mid-write leaves the stored resource as it was, tells the
// client nothing about the cause, and reports it to ErrorLog.
func TestBackendFailureIsAtomicAndOpaque(t *testing.T) {
	fb := &failingBackend{Memory: NewMemory()}
	var logged atomic.Int32
	srv := &Server{Backend: fb, ErrorLog: func(error) { logged.Add(1) }}
	do := func(method, path, body string) (int, string) {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, r)
		return w.Code, w.Body.String()
	}
	if code, b := do("POST", "/Users", userBody); code != 201 {
		t.Fatal(code, b)
	}
	var id string
	us, _ := fb.Memory.ListUsers(context.Background(), nil)
	id = us[0].ID
	fb.failReplace.Store(true)
	fb.failList.Store(true)
	for _, c := range []struct{ m, p, b string }{
		{"PATCH", "/Users/" + id, patchBody(`[{"op":"replace","path":"displayName","value":"x"}]`)},
		{"PUT", "/Users/" + id, `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"bob"}`},
		{"GET", "/Users", ""},
		{"POST", "/Users/.search", `{}`},
	} {
		code, body := do(c.m, c.p, c.b)
		if code != 500 || strings.Contains(body, "secret") || strings.Contains(body, "hunter2") || strings.Contains(body, "disk") {
			t.Errorf("%s %s: %d %s", c.m, c.p, code, body)
		}
	}
	if logged.Load() != 4 {
		t.Errorf("%d errors logged, want 4", logged.Load())
	}
	fb.failReplace.Store(false)
	fb.failList.Store(false)
	u, err := fb.Memory.GetUser(context.Background(), id)
	if err != nil || u.UserName != "alice" || u.DisplayName != "" {
		t.Fatalf("the user changed under a failed write: %+v %v", u, err)
	}
}

// toMap on a User or Group must be the JSON round trip, field for field.
func TestToMapMatchesJSON(t *testing.T) {
	yes, no := Bool(true), Bool(false)
	now := time.Date(2026, 10, 24, 1, 2, 3, 456789000, time.FixedZone("x", 3600))
	meta := Meta{ResourceType: "User", Created: now, LastModified: now.Add(time.Second), Location: "/Users/1", Version: `W/"v"`}
	users := []*User{
		{},
		{Schemas: []string{UserSchema}, ID: "1", UserName: "a", Meta: meta},
		{Schemas: []string{UserSchema}, ID: "1", ExternalID: "e", UserName: "a", DisplayName: "A \"q\" <é>\u2028", Active: &yes,
			Name:   &Name{Formatted: "f", FamilyName: "F", GivenName: "G", MiddleName: "M", HonorificPrefix: "P", HonorificSuffix: "S"},
			Emails: []Email{{Value: "x"}, {Value: "y", Type: "work", Display: "d", Primary: true}},
			Groups: []Ref{{Value: "g", Ref: "/Groups/g", Display: "G", Type: "direct"}, {Value: "h"}}, Meta: meta},
		{UserName: "z", Active: &no, Name: &Name{}, Emails: []Email{}, Groups: []Ref{}},
	}
	groups := []*Group{
		{},
		{Schemas: []string{GroupSchema}, ID: "g", DisplayName: "G", Meta: meta},
		{Schemas: []string{GroupSchema}, ID: "g", ExternalID: "e", DisplayName: "G", Members: []Ref{{Value: "1", Ref: "r", Display: "d", Type: "User"}, {Value: "2"}}, Meta: meta},
	}
	var all []any
	for _, u := range users {
		all = append(all, u)
	}
	for _, g := range groups {
		all = append(all, g)
	}
	for i, v := range all {
		want, err := jsonMap(v)
		if err != nil {
			t.Fatal(err)
		}
		got, err := toMap(v)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("#%d:\n got %#v\nwant %#v", i, got, want)
		}
	}
}

// TestListIsConsistent: listing with and without a filter returns the same
// resources the single-resource endpoints show.
func TestListMatchesGet(t *testing.T) {
	c, _ := newClient(t)
	for i := 0; i < 5; i++ {
		c.want(201, "POST", "/Users", fmt.Sprintf(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"u%d","emails":[{"value":"u%d@x"}]}`, i, i))
	}
	c.want(201, "POST", "/Groups", `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"g","members":[{"value":"id-002"},{"value":"id-004"}]}`)
	list := c.want(200, "GET", "/Users?filter="+"userName%20sw%20%22U%22", "")
	res, _ := list["Resources"].([]any)
	if len(res) != 5 {
		t.Fatalf("%d resources", len(res))
	}
	for _, r := range res {
		rm := r.(map[string]any)
		one := c.want(200, "GET", "/Users/"+rm["id"].(string), "")
		if !reflect.DeepEqual(rm, one) {
			t.Errorf("list %v\n get  %v", rm, one)
		}
	}
	eq := c.want(200, "GET", "/Users?filter=userName%20eq%20%22U3%22", "")
	if eq["totalResults"] != float64(1) {
		t.Fatalf("eq: %v", eq)
	}
	by := c.want(200, "GET", "/Users?filter=groups%5Bvalue%20eq%20%22id-006%22%5D", "")
	if by["totalResults"] != float64(2) {
		t.Fatalf("groups filter: %v", by)
	}
}
