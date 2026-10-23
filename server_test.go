package scim

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

type client struct {
	t     testing.TB
	h     http.Handler
	token string
}

func newClient(t testing.TB) (*client, *Memory) {
	mem := NewMemory()
	n := 0
	var mu sync.Mutex
	srv := &Server{
		Backend: mem, BaseURL: "https://app.example/scim/v2",
		Now:      func() time.Time { return time.Date(2026, 10, 24, 0, 0, 0, 0, time.UTC) },
		NewID:    func() string { mu.Lock(); defer mu.Unlock(); n++; return fmt.Sprintf("id-%03d", n) },
		ErrorLog: func(error) {},
	}
	return &client{t: t, h: BearerAuth("s3cret-token", srv), token: "s3cret-token"}, mem
}

func (c *client) do(method, path, body string, hdr ...string) (int, map[string]any, http.Header) {
	c.t.Helper()
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.Header.Set("Authorization", "Bearer "+c.token)
	r.Header.Set("Content-Type", MediaType)
	for i := 0; i+1 < len(hdr); i += 2 {
		r.Header.Set(hdr[i], hdr[i+1])
	}
	w := httptest.NewRecorder()
	c.h.ServeHTTP(w, r)
	var m map[string]any
	b, _ := io.ReadAll(w.Body)
	if len(b) > 0 {
		if err := json.Unmarshal(b, &m); err != nil {
			c.t.Fatalf("%s %s: not JSON: %s", method, path, b)
		}
		if w.Header().Get("Content-Type") != MediaType {
			c.t.Fatalf("%s %s: content type %q", method, path, w.Header().Get("Content-Type"))
		}
	}
	return w.Code, m, w.Header()
}

func (c *client) want(status int, method, path, body string, hdr ...string) map[string]any {
	c.t.Helper()
	got, m, _ := c.do(method, path, body, hdr...)
	if got != status {
		c.t.Fatalf("%s %s: %d %v, want %d", method, path, got, m, status)
	}
	return m
}

func errType(m map[string]any) string {
	s, _ := m["scimType"].(string)
	return s
}

// The provisioning an Entra ID SCIM client performs, with its request
// bodies (Microsoft Learn, "Develop and plan provisioning for a SCIM
// endpoint"), including its "Replace"/"Add" capitals and its string
// booleans.
func TestEntraFlow(t *testing.T) {
	c, _ := newClient(t)
	u := c.want(201, "POST", "/Users", `{
		"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User", "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"],
		"externalId": "0a21f0f2-8d2a-4f8e-bf98-7363c4aed4ef",
		"userName": "Test_User_ab6490ee@testuser.com",
		"active": true,
		"emails": [{"primary": true, "type": "work", "value": "Test_User_fd0ea19b@testuser.com"}],
		"meta": {"resourceType": "User"},
		"name": {"formatted": "givenName familyName", "familyName": "familyName", "givenName": "givenName"},
		"roles": []
	}`)
	id := u["id"].(string)
	if id != "id-001" || u["meta"].(map[string]any)["location"] != "https://app.example/scim/v2/Users/id-001" {
		t.Fatalf("created %v", u)
	}
	// Duplicate userName, in another case.
	m := c.want(409, "POST", "/Users", `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"TEST_USER_AB6490EE@testuser.com"}`)
	if errType(m) != "uniqueness" || m["status"] != "409" {
		t.Fatalf("conflict %v", m)
	}
	// Entra's lookups.
	list := c.want(200, "GET", `/Users?filter=userName+eq+%22Test_User_ab6490ee%40testuser.com%22`, "")
	if list["totalResults"].(float64) != 1 {
		t.Fatalf("filter %v", list)
	}
	list = c.want(200, "GET", `/Users?filter=userName+eq+%22non-existent%22`, "")
	if list["totalResults"].(float64) != 0 || len(list["Resources"].([]any)) != 0 {
		t.Fatalf("empty filter %v", list)
	}
	// Patch with Entra's spelling.
	u = c.want(200, "PATCH", "/Users/"+id, `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[
		{"op":"Replace","path":"emails[type eq \"work\"].value","value":"updatedEmail@microsoft.com"},
		{"op":"Replace","path":"name.familyName","value":"updatedFamilyName"}]}`)
	if u["emails"].([]any)[0].(map[string]any)["value"] != "updatedEmail@microsoft.com" || u["name"].(map[string]any)["familyName"] != "updatedFamilyName" {
		t.Fatalf("patched %v", u)
	}
	// Disable, with the string boolean Entra sends.
	u = c.want(200, "PATCH", "/Users/"+id, `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"Replace","path":"active","value":"False"}]}`)
	if u["active"] != false {
		t.Fatalf("disabled %v", u)
	}
	// A group, its members added and removed.
	g := c.want(201, "POST", "/Groups", `{"externalId":"8aa1a0c0-c4c3-4bc0-b4a5-2ef676900159","displayName":"displayName","meta":{"resourceType":"Group"},"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"]}`)
	gid := g["id"].(string)
	c.want(200, "PATCH", "/Groups/"+gid, `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"Add","path":"members","value":[{"$ref":null,"value":"`+id+`"}]}]}`)
	u = c.want(200, "GET", "/Users/"+id, "")
	if gs, _ := u["groups"].([]any); len(gs) != 1 || gs[0].(map[string]any)["value"] != gid {
		t.Fatalf("user's groups %v", u["groups"])
	}
	g = c.want(200, "GET", "/Groups/"+gid+"?excludedAttributes=members", "")
	if _, has := g["members"]; has || g["displayName"] != "displayName" {
		t.Fatalf("excluded members %v", g)
	}
	list = c.want(200, "GET", `/Groups?filter=displayName+eq+%22displayName%22&excludedAttributes=members`, "")
	if list["totalResults"].(float64) != 1 {
		t.Fatalf("group filter %v", list)
	}
	c.want(200, "PATCH", "/Groups/"+gid, `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"Remove","path":"members[value eq \"`+id+`\"]"}]}`)
	g = c.want(200, "GET", "/Groups/"+gid, "")
	if _, has := g["members"]; has {
		t.Fatalf("member not removed %v", g)
	}
	// Remove with a value list (Entra's other spelling).
	c.want(200, "PATCH", "/Groups/"+gid, `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"add","path":"members","value":[{"value":"`+id+`"}]}]}`)
	c.want(200, "PATCH", "/Groups/"+gid, `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"remove","path":"members","value":[{"value":"`+id+`"}]}]}`)
	if g = c.want(200, "GET", "/Groups/"+gid, ""); g["members"] != nil {
		t.Fatalf("member not removed by value %v", g)
	}
	// A work email created through a filtered add.
	u = c.want(200, "PATCH", "/Users/"+id, `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"Add","path":"emails[type eq \"home\"].value","value":"home@example.org"}]}`)
	if len(u["emails"].([]any)) != 2 {
		t.Fatalf("filtered add %v", u["emails"])
	}
	c.want(204, "DELETE", "/Users/"+id, "")
	c.want(404, "GET", "/Users/"+id, "")
	c.want(404, "DELETE", "/Users/"+id, "")
	c.want(204, "DELETE", "/Groups/"+gid, "")
}

// Okta replaces a group by a patch without a path, repeating its id.
func TestOktaFlow(t *testing.T) {
	c, _ := newClient(t)
	u := c.want(201, "POST", "/Users", `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"okta@example.com","name":{"givenName":"O","familyName":"K"},"active":true,"emails":[{"value":"okta@example.com","type":"work","primary":true}]}`)
	id := u["id"].(string)
	g := c.want(201, "POST", "/Groups", `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"Test SCIMv2","members":[]}`)
	gid := g["id"].(string)
	g = c.want(200, "PATCH", "/Groups/"+gid, `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","value":{"id":"`+gid+`","displayName":"Renamed"}}]}`)
	if g["displayName"] != "Renamed" {
		t.Fatalf("renamed %v", g)
	}
	m := c.want(400, "PATCH", "/Groups/"+gid, `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","value":{"id":"other"}}]}`)
	if errType(m) != "mutability" {
		t.Fatalf("id change %v", m)
	}
	g = c.want(200, "PATCH", "/Groups/"+gid, `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"members","value":[{"value":"`+id+`","display":"okta@example.com"}]}]}`)
	if ms := g["members"].([]any); len(ms) != 1 || ms[0].(map[string]any)["type"] != "User" {
		t.Fatalf("members %v", g)
	}
	u = c.want(200, "PATCH", "/Users/"+id, `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","value":{"active":false}}]}`)
	if u["active"] != false {
		t.Fatalf("deactivated %v", u)
	}
	// PUT replaces; groups in the body are ignored (read-only).
	u = c.want(200, "PUT", "/Users/"+id, `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"id":"ignored","userName":"okta2@example.com","groups":[{"value":"x"}]}`)
	if u["id"] != id || u["userName"] != "okta2@example.com" || u["name"] != nil {
		t.Fatalf("put %v", u)
	}
	if gs := u["groups"].([]any); len(gs) != 1 {
		t.Fatalf("groups after put %v", u["groups"])
	}
}

func TestRefusals(t *testing.T) {
	c, _ := newClient(t)
	u := c.want(201, "POST", "/Users", `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"bjensen"}`)
	id := u["id"].(string)
	patch := func(ops string) string {
		return `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":` + ops + `}`
	}
	for _, tc := range []struct {
		method, path, body string
		status             int
		scimType           string
	}{
		{"POST", "/Users", `{"userName":"x"}`, 400, "invalidSyntax"},
		{"POST", "/Users", `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"]}`, 400, "invalidValue"},
		{"POST", "/Users", `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"a\u0000b"}`, 400, "invalidValue"},
		{"POST", "/Users", `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":5}`, 400, "invalidValue"},
		{"POST", "/Users", `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"x","active":"maybe"}`, 400, "invalidValue"},
		{"POST", "/Users", `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"x","emails":[{"value":"a","primary":true},{"value":"b","primary":true}]}`, 400, "invalidValue"},
		{"POST", "/Users", `not json`, 400, "invalidSyntax"},
		{"POST", "/Groups", `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"]}`, 400, "invalidValue"},
		{"POST", "/Groups", `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"g","members":[{"value":"nobody"}]}`, 400, "invalidValue"},
		{"POST", "/Groups", `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"g","members":[{"display":"no value"}]}`, 400, "invalidValue"},
		{"GET", "/Users?filter=userName+xx+%22a%22", "", 400, "invalidFilter"},
		{"GET", "/Users?count=abc", "", 400, "invalidValue"},
		{"PATCH", "/Users/" + id, `{"Operations":[{"op":"add","path":"title","value":"x"}]}`, 400, "invalidSyntax"},
		{"PATCH", "/Users/" + id, patch(`[]`), 400, "invalidValue"},
		{"PATCH", "/Users/" + id, patch(`[{"op":"move","path":"title","value":"x"}]`), 400, "invalidSyntax"},
		{"PATCH", "/Users/" + id, patch(`[{"op":"remove"}]`), 400, "noTarget"},
		{"PATCH", "/Users/" + id, patch(`[{"op":"replace","path":"id","value":"x"}]`), 400, "mutability"},
		{"PATCH", "/Users/" + id, patch(`[{"op":"add","path":"groups","value":[{"value":"g"}]}]`), 400, "mutability"},
		{"PATCH", "/Users/" + id, patch(`[{"op":"replace","path":"meta.created","value":"x"}]`), 400, "mutability"},
		{"PATCH", "/Users/" + id, patch(`[{"op":"replace","path":"emails[type eq \"work\"].value","value":"x"}]`), 400, "noTarget"},
		{"PATCH", "/Users/" + id, patch(`[{"op":"replace","path":"emails[type eq","value":"x"}]`), 400, "invalidPath"},
		{"PATCH", "/Users/" + id, patch(`[{"op":"replace","path":"1bad","value":"x"}]`), 400, "invalidPath"},
		{"PATCH", "/Users/" + id, patch(`[{"op":"replace","path":"userName","value":""}]`), 400, "invalidValue"},
		{"PATCH", "/Users/" + id, patch(`[{"op":"replace","path":"userName"}]`), 400, "invalidValue"},
		{"PATCH", "/Users/" + id, patch(`[{"op":"replace","value":"not an object"}]`), 400, "invalidValue"},
		{"PATCH", "/Users/" + id, patch(`[{"op":"replace","path":"userName","value":{"a":1}}]`), 400, "invalidValue"},
		{"PATCH", "/Users/nobody", patch(`[{"op":"replace","path":"title","value":"x"}]`), 404, ""},
		{"PUT", "/Users/nobody", `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"n"}`, 404, ""},
		{"GET", "/Bulk", "", 404, ""},
		{"GET", "/Users/a/b", "", 404, ""},
		{"PUT", "/Users", "", 405, ""},
		{"POST", "/ServiceProviderConfig", "", 405, ""},
		{"GET", "/Schemas?filter=a+pr", "", 403, ""},
		{"GET", "/Schemas/urn:nope", "", 404, ""},
		{"GET", "/ResourceTypes/Nope", "", 404, ""},
		{"GET", "/ServiceProviderConfig/x", "", 404, ""},
		{"POST", "/Users/.search", `{"filter":"a xx 1"}`, 400, "invalidFilter"},
		{"POST", "/Users/.search", `[`, 400, "invalidSyntax"},
	} {
		got, m, _ := c.do(tc.method, tc.path, tc.body)
		if got != tc.status || errType(m) != tc.scimType {
			t.Errorf("%s %s %s: %d %v, want %d %s", tc.method, tc.path, tc.body, got, m, tc.status, tc.scimType)
		}
		if got >= 400 && (m["status"] != fmt.Sprint(got) || m["schemas"].([]any)[0] != ErrorSchema) {
			t.Errorf("%s %s: error body %v", tc.method, tc.path, m)
		}
	}
	// A failed PATCH changes nothing (atomic).
	c.want(400, "PATCH", "/Users/"+id, patch(`[{"op":"replace","path":"displayName","value":"changed"},{"op":"replace","path":"id","value":"x"}]`))
	if u = c.want(200, "GET", "/Users/"+id, ""); u["displayName"] != nil {
		t.Fatalf("half-applied patch: %v", u)
	}
}

func TestAuth(t *testing.T) {
	c, _ := newClient(t)
	c.token = "wrong"
	got, m, h := c.do("GET", "/Users", "")
	if got != 401 || h.Get("WWW-Authenticate") == "" || m["status"] != "401" {
		t.Fatalf("wrong token: %d %v", got, m)
	}
	h2 := BearerAuth("", NewMemoryServer())
	r := httptest.NewRequest("GET", "/Users", nil)
	r.Header.Set("Authorization", "Bearer ")
	w := httptest.NewRecorder()
	h2.ServeHTTP(w, r)
	if w.Code != 401 {
		t.Fatalf("empty token admitted: %d", w.Code)
	}
}

// NewMemoryServer is a Server over a fresh Memory backend.
func NewMemoryServer() *Server { return &Server{Backend: NewMemory()} }

func TestPagingAndProjection(t *testing.T) {
	c, _ := newClient(t)
	for i := range 7 {
		c.want(201, "POST", "/Users", fmt.Sprintf(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"u%d","displayName":"User %d","name":{"givenName":"G%d","familyName":"F"}}`, i, i, i))
	}
	page := func(q string) ([]string, float64, float64, float64) {
		m := c.want(200, "GET", "/Users?"+q, "")
		var names []string
		for _, r := range m["Resources"].([]any) {
			names = append(names, fmt.Sprint(r.(map[string]any)["userName"]))
		}
		return names, m["totalResults"].(float64), m["startIndex"].(float64), m["itemsPerPage"].(float64)
	}
	if names, total, start, per := page("startIndex=3&count=2"); fmt.Sprint(names) != "[u2 u3]" || total != 7 || start != 3 || per != 2 {
		t.Fatalf("page: %v %v %v %v", names, total, start, per)
	}
	if names, _, start, _ := page("startIndex=-5&count=1"); fmt.Sprint(names) != "[u0]" || start != 1 {
		t.Fatalf("startIndex below 1: %v %v", names, start)
	}
	if names, total, _, per := page("count=-1"); len(names) != 0 || total != 7 || per != 0 {
		t.Fatalf("negative count: %v", names)
	}
	if names, _, _, _ := page("startIndex=100"); len(names) != 0 {
		t.Fatalf("past the end: %v", names)
	}
	if names, _, _, _ := page("count=1000000"); len(names) != 7 {
		t.Fatalf("clamped count: %v", names)
	}
	m := c.want(200, "GET", "/Users?attributes=userName,name.givenName&count=1", "")
	r0 := m["Resources"].([]any)[0].(map[string]any)
	if r0["id"] == nil || r0["schemas"] == nil || r0["userName"] != "u0" || r0["displayName"] != nil || r0["meta"] != nil {
		t.Fatalf("attributes: %v", r0)
	}
	if n := r0["name"].(map[string]any); n["givenName"] != "G0" || n["familyName"] != nil {
		t.Fatalf("sub-attribute projection: %v", n)
	}
	m = c.want(200, "GET", "/Users?excludedAttributes=displayName,name.familyName,id&count=1", "")
	r0 = m["Resources"].([]any)[0].(map[string]any)
	if r0["displayName"] != nil || r0["id"] == nil || r0["name"].(map[string]any)["familyName"] != nil {
		t.Fatalf("excludedAttributes: %v", r0)
	}
	m = c.want(200, "POST", "/Users/.search", `{"schemas":["urn:ietf:params:scim:api:messages:2.0:SearchRequest"],"filter":"displayName sw \"user\"","startIndex":2,"count":2,"attributes":["userName"],"excludedAttributes":["x"]}`)
	if m["totalResults"].(float64) != 7 || len(m["Resources"].([]any)) != 2 {
		t.Fatalf(".search: %v", m)
	}
}

func TestETags(t *testing.T) {
	c, mem := newClient(t)
	_, u, h := c.do("POST", "/Users", `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"etag"}`)
	id, v := u["id"].(string), h.Get("ETag")
	if !strings.HasPrefix(v, `W/"`) || u["meta"].(map[string]any)["version"] != v {
		t.Fatalf("etag %q / %v", v, u["meta"])
	}
	if got, _, _ := c.do("GET", "/Users/"+id, "", "If-None-Match", v); got != 304 {
		t.Fatalf("If-None-Match: %d", got)
	}
	c.want(412, "PUT", "/Users/"+id, `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"x"}`, "If-Match", `W/"stale"`)
	c.want(412, "DELETE", "/Users/"+id, "", "If-Match", `W/"stale"`)
	_, _, h = c.do("PUT", "/Users/"+id, `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"x"}`, "If-Match", v)
	if nv := h.Get("ETag"); nv == "" || nv == v {
		t.Fatalf("version not changed: %q", nv)
	}
	// A concurrent change between the read and the write of a PATCH is
	// detected by the backend, not overwritten.
	cur, _ := mem.GetUser(t.Context(), id)
	if err := mem.ReplaceUser(t.Context(), cur, `W/"other"`); !errors.Is(err, ErrPrecondition) {
		t.Fatalf("stale replace: %v", err)
	}
	c.want(204, "DELETE", "/Users/"+id, "", "If-Match", "*")
}

func TestDiscovery(t *testing.T) {
	c, _ := newClient(t)
	m := c.want(200, "GET", "/ServiceProviderConfig", "")
	if m["patch"].(map[string]any)["supported"] != true || m["filter"].(map[string]any)["maxResults"].(float64) != 100 {
		t.Fatalf("config %v", m)
	}
	m = c.want(200, "GET", "/ResourceTypes", "")
	if m["totalResults"].(float64) != 2 {
		t.Fatalf("resource types %v", m)
	}
	c.want(200, "GET", "/ResourceTypes/User", "")
	c.want(200, "GET", "/ResourceTypes/Group", "")
	m = c.want(200, "GET", "/Schemas", "")
	if m["totalResults"].(float64) != 2 {
		t.Fatalf("schemas %v", m)
	}
	m = c.want(200, "GET", "/Schemas/"+UserSchema, "")
	if m["id"] != UserSchema || len(m["attributes"].([]any)) == 0 {
		t.Fatalf("user schema %v", m)
	}
	c.want(200, "GET", "/Schemas/"+GroupSchema, "")
}

func TestBodyLimits(t *testing.T) {
	mem := NewMemory()
	srv := &Server{Backend: mem, MaxBodyBytes: 512, MaxOperations: 2, MaxMembers: 2}
	c := &client{t: t, h: srv}
	c.want(413, "POST", "/Users", `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"`+strings.Repeat("x", 600)+`"}`)
	u := c.want(201, "POST", "/Users", `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"a"}`)
	c.want(413, "PATCH", "/Users/"+u["id"].(string), `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"add","path":"a","value":1},{"op":"add","path":"b","value":1},{"op":"add","path":"c","value":1}]}`)
	c.want(400, "POST", "/Groups", `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"g","members":[{"value":"a"},{"value":"b"},{"value":"c"}]}`)
	// A PATCH that grows the resource past the limit.
	c.want(413, "PATCH", "/Users/"+u["id"].(string), `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"add","path":"displayName","value":"`+strings.Repeat("y", 300)+`"},{"op":"add","path":"title","value":"`+strings.Repeat("y", 150)+`"}]}`)
}

// A backend error that is not a sentinel is a 500 that says nothing.
type brokenBackend struct{ *Memory }

func (b *brokenBackend) ListUsers(context.Context, *Filter) ([]User, error) {
	return nil, errors.New("pq: password authentication failed for user secret")
}

func TestInternalErrorIsOpaque(t *testing.T) {
	var logged error
	srv := &Server{Backend: &brokenBackend{Memory: NewMemory()}, ErrorLog: func(err error) { logged = err }}
	c := &client{t: t, h: srv}
	m := c.want(500, "GET", "/Users", "")
	if strings.Contains(fmt.Sprint(m), "password") || logged == nil {
		t.Fatalf("500 body %v, logged %v", m, logged)
	}
}
