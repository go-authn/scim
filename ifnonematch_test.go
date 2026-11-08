package scim

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestIfNoneMatchGET follows RFC 7232 §3.2 (If-None-Match = "*" / 1#entity-tag,
// weak comparison, 304 for GET when the condition is false) and the
// comparison table of §2.3.2.
func TestIfNoneMatchGET(t *testing.T) {
	c, _ := newClient(t)
	_, u, h := c.do("POST", "/Users", `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"inm"}`)
	id, v := u["id"].(string), h.Get("ETag")
	opaque := strings.TrimPrefix(v, "W/") // the current tag, written as a strong one

	cases := []struct {
		name   string
		header string
		want   int
	}{
		{"same weak tag", v, 304},
		{"strong spelling of the weak tag (§2.3.2: W/\"1\" vs \"1\" matches weakly)", opaque, 304},
		{"list, match last", `W/"a", W/"b", ` + v, 304},
		{"list, match first, no spaces", v + `,W/"b"`, 304},
		{"list, match middle, strong spelling", `"a", ` + opaque + `, "b"`, 304},
		{"list, tabs and spaces around commas", "W/\"a\" \t,\t " + v, 304},
		{"empty list elements are ignored (§3.2 #rule, RFC 7230 §7)", `, ,` + v + `,`, 304},
		{"star matches any current representation", `*`, 304},
		{"star with surrounding whitespace", ` * `, 304},
		{"list, no match", `W/"a", "b"`, 200},
		{"different weak tag", `W/"other"`, 200},
		{"star inside a list is not valid", `*, ` + v, 200},
		{"unquoted tag is not an entity-tag", strings.Trim(opaque, `"`), 200},
		{"lower-case w/ is not a weak indicator", `w/` + opaque, 200},
		{"truncated tag", v[:len(v)-1], 200},
	}
	for _, tc := range cases {
		got, body, hdr := c.do("GET", "/Users/"+id, "", "If-None-Match", tc.header)
		if got != tc.want {
			t.Errorf("%s: If-None-Match %q: status %d, want %d", tc.name, tc.header, got, tc.want)
			continue
		}
		if got == 304 {
			// RFC 7232 §4.1: a 304 carries the ETag a 200 would have had.
			if hdr.Get("ETag") != v || body != nil {
				t.Errorf("%s: 304 with ETag %q, body %v", tc.name, hdr.Get("ETag"), body)
			}
		} else if hdr.Get("ETag") != v || body["id"] != id {
			t.Errorf("%s: 200 without the representation: ETag %q body %v", tc.name, hdr.Get("ETag"), body)
		}
	}

	// A list may arrive as several header lines (RFC 7230 §3.2.2).
	r := httptest.NewRequest(http.MethodGet, "/Users/"+id, nil)
	r.Header.Set("Authorization", "Bearer s3cret-token")
	r.Header.Add("If-None-Match", `W/"a"`)
	r.Header.Add("If-None-Match", v)
	w := httptest.NewRecorder()
	c.h.ServeHTTP(w, r)
	if w.Code != 304 {
		t.Errorf("two If-None-Match lines: %d, want 304", w.Code)
	}

	// "*" needs a current representation: an absent resource stays 404.
	c.want(404, "GET", "/Users/nobody", "", "If-None-Match", "*")
	// Groups share the code path.
	_, g, gh := c.do("POST", "/Groups", `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"g"}`)
	if got, _, _ := c.do("GET", "/Groups/"+g["id"].(string), "", "If-None-Match", `W/"a", `+gh.Get("ETag")); got != 304 {
		t.Errorf("group list: %d", got)
	}
}
