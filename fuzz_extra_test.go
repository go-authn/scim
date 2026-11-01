package scim

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

// FuzzPatchPath: a PATCH path is parsed to a value or refused with a 400
// invalidPath, never a panic and never another error.
func FuzzPatchPath(f *testing.F) {
	for _, s := range []string{
		`name.givenName`, `emails[type eq "work"].value`, `members[value eq "x"]`, `urn:ietf:params:scim:schemas:core:2.0:User:userName`,
		`emails[`, `emails]`, `emails[type eq "a"]x`, `a[b[c]]`, `emails[type eq "work"].`, `[`, `.`, ``, `$ref`, `a.b.c`,
		`urn:x:y:z.w`, `emails[not (type eq "a")].value`,
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		_, err := parsePatchPath(s)
		if err != nil && (err.Status != 400 || err.ScimType != "invalidPath") {
			t.Fatalf("%q: %v", s, err)
		}
	})
}

// FuzzPatchThenDecode: whatever a PATCH does to a user, the result is either
// refused with a 400 or is a valid user that survives a JSON round trip and
// never carries a password-like attribute the schema does not model.
func FuzzPatchThenDecode(f *testing.F) {
	f.Add(`[{"op":"add","path":"emails","value":[{"value":"a@b","primary":true}]}]`)
	f.Add(`[{"op":"replace","value":{"password":"hunter2","userName":"x"}}]`)
	f.Add(`[{"op":"add","path":"password","value":"hunter2"}]`)
	f.Fuzz(func(t *testing.T, ops string) {
		var o []PatchOp
		if json.Unmarshal([]byte(ops), &o) != nil || len(o) > 16 {
			return
		}
		s := &Server{}
		m, _ := toMap(&User{Schemas: []string{UserSchema}, ID: "1", UserName: "alice", Emails: []Email{{Value: "a@b"}}})
		if e := applyPatch(m, o, map[string]bool{"id": true, "meta": true, "schemas": true, "groups": true}); e != nil {
			return
		}
		b, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		res, e := s.decode(b, resourceUser)
		if e != nil {
			if e.Status != 400 {
				t.Fatalf("%s: %v", b, e)
			}
			return
		}
		out, err := json.Marshal(res)
		if err != nil || strings.Contains(strings.ToLower(string(out)), "password") {
			t.Fatalf("%s -> %s (%v)", b, out, err)
		}
	})
}

// A password sent on create, replace or PATCH is never stored and never
// returned (RFC 7643 §4.1.1: returned "never"; this server models none).
func TestPasswordIsNeverReturned(t *testing.T) {
	c, mem := newClient(t)
	created := c.want(201, "POST", "/Users", `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"alice","password":"hunter2","Password":"hunter3"}`)
	c.want(200, "PATCH", "/Users/id-001", patchBody(`[{"op":"add","path":"password","value":"hunter4"},{"op":"add","value":{"PASSWORD":"hunter5"}}]`))
	c.want(200, "PUT", "/Users/id-001", `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"alice","password":"hunter6"}`)
	for _, path := range []string{"/Users/id-001", "/Users", "/Users?filter=userName%20pr&attributes=password"} {
		_, m, _ := c.do("GET", path, "")
		b, _ := json.Marshal(m)
		if strings.Contains(strings.ToLower(string(b)), "hunter") || strings.Contains(strings.ToLower(string(b)), "password") {
			t.Errorf("%s: %s", path, b)
		}
	}
	if b, _ := json.Marshal(created); strings.Contains(string(b), "hunter") {
		t.Errorf("create: %s", b)
	}
	us, _ := mem.ListUsers(context.Background(), nil)
	if b, _ := json.Marshal(us); strings.Contains(string(b), "hunter") {
		t.Errorf("stored: %s", b)
	}
}

// A filter at the size limit, built to be as slow as possible, is parsed and
// matched against a fat resource in well under a second, and nesting beyond
// the bound is refused, not recursed into.
func TestFilterWorstCaseIsBounded(t *testing.T) {
	var emails []Email
	for i := 0; i < 100; i++ {
		emails = append(emails, Email{Value: fmt.Sprintf("user%d@example.org", i), Type: "work"})
	}
	m, _ := toMap(&User{Schemas: []string{UserSchema}, ID: "1", UserName: "alice", Emails: emails})
	for name, clause := range map[string]string{
		"pr":        `userName pr`,
		"valuepath": `emails[type eq "home" and value co "zz"]`,
		"sub":       `emails.value ew "zz"`,
		"not":       `not (emails.value sw "zz")`,
	} {
		var b strings.Builder
		for b.Len()+2*len(clause)+5 < MaxFilterBytes {
			b.WriteString(clause + " and ")
		}
		b.WriteString(clause)
		src := b.String()
		start := time.Now()
		fl, err := ParseFilter(src)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		for i := 0; i < 100; i++ {
			fl.Match(m)
		}
		if d := time.Since(start); d > 5*time.Second {
			t.Errorf("%s: 100 matches of a %d-byte filter took %v", name, len(src), d)
		}
	}
	for _, src := range []string{strings.Repeat("(", 40) + "a pr" + strings.Repeat(")", 40), strings.Repeat("not (", 40) + "a pr" + strings.Repeat(")", 40)} {
		_, err := ParseFilter(src)
		var se *Error
		if !errors.As(err, &se) || se.ScimType != "invalidFilter" {
			t.Errorf("%.20s...: %v", src, err)
		}
	}
	if _, err := ParseFilter(strings.Repeat("a", MaxFilterBytes+1)); err == nil {
		t.Error("an oversized filter was accepted")
	}
}

// A filter value is data, never syntax: whatever a client puts in it comes
// back as the same literal (the Backend hint gets the decoded string).
func TestFilterValueIsData(t *testing.T) {
	for _, v := range []string{`x" or userName pr or userName eq "y`, `'; DROP TABLE users; --`, `*)(uid=*))(|(uid=*`, `\u0000`, "a\\\"b"} {
		lit, _ := json.Marshal(v)
		fl, err := ParseFilter(`userName eq ` + string(lit))
		if err != nil {
			t.Fatalf("%q: %v", v, err)
		}
		attr, got, ok := fl.Equality()
		if !ok || attr != "username" || got != v {
			t.Errorf("%q: attr %q value %q ok=%v", v, attr, got, ok)
		}
	}
}
