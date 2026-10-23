package scim

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

const alice = `{
  "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User", "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"],
  "id": "2819c223-7f76-453a-919d-413861904646",
  "externalId": "Alice-Ext",
  "userName": "Alice@Example.com",
  "name": {"familyName": "Liddell", "givenName": "Alice"},
  "active": true,
  "emails": [
    {"value": "alice@example.com", "type": "work", "primary": true},
    {"value": "alice@home.example", "type": "home"}
  ],
  "loginCount": 42,
  "meta": {"resourceType": "User", "created": "2026-01-23T04:56:22Z", "lastModified": "2026-05-13T04:42:34Z", "version": "W/\"a330bc54f0671c9\""},
  "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User": {"employeeNumber": "701984", "department": "Tour Operations"}
}`

func asMap(t *testing.T, s string) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestFilterMatch(t *testing.T) {
	m := asMap(t, alice)
	for f, want := range map[string]bool{
		// RFC 7644 §3.4.2.2 examples, adapted to this resource.
		`userName eq "alice@example.com"`: true, // userName is not caseExact
		`USERNAME EQ "ALICE@EXAMPLE.COM"`: true, // nor are names and operators
		`userName eq "bob@example.com"`:   false,
		`name.familyName co "dde"`:        true,
		`userName sw "ali"`:               true,
		`userName ew ".com"`:              true,
		`urn:ietf:params:scim:schemas:core:2.0:User:name.familyName co "iddel"`: true,
		`title pr`:  false,
		`emails pr`: true,
		`name pr`:   true,
		`meta.lastModified gt "2026-05-01T00:00:00Z"`:                             true,
		`meta.lastModified lt "2026-05-01T00:00:00Z"`:                             false,
		`meta.lastModified ge "2026-05-13T04:42:34Z"`:                             true,
		`meta.lastModified le "2026-05-13T04:42:33Z"`:                             false,
		`emails co "home.example"`:                                                true, // through emails.value
		`emails.type eq "work"`:                                                   true,
		`emails[type eq "work" and value co "@example.com"]`:                      true,
		`emails[type eq "home" and value co "@example.com"]`:                      false,
		`userName eq "alice@example.com" and name.givenName eq "Alice"`:           true,
		`userName eq "x" or name.givenName eq "alice"`:                            true,
		`not (userName eq "x")`:                                                   true,
		`not(userName eq "alice@example.com")`:                                    false,
		`userName eq "x" or userName eq "y" and active eq true`:                   false,
		`(userName eq "x" or userName eq "alice@example.com") and active eq true`: true,
		`active eq true`:     true,
		`active ne true`:     false,
		`active eq false`:    false,
		`title eq null`:      true,
		`title ne null`:      false,
		`userName ne null`:   true,
		`loginCount gt 41`:   true,
		`loginCount le 41.5`: false,
		`loginCount eq 42`:   true,
		`userName gt 3`:      false, // type mismatch matches nothing
		`id eq "2819C223-7F76-453A-919D-413861904646"`: false, // id is caseExact
		`externalId eq "alice-ext"`:                    false, // so is externalId
		`externalId eq "Alice-Ext"`:                    true,
		`meta.version eq "w/\"A330BC54F0671C9\""`:      false,
		`urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:employeeNumber eq "701984"`: true,
		`urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:department sw "tour"`:       true,
		`urn:ietf:params:scim:schemas:extension:other:2.0:User:x pr`:                            false,
		`emails ne "alice@example.com"`:                                                         false,
		`emails.value eq "ALICE@HOME.EXAMPLE"`:                                                  true,
		`name eq "Alice"`:                                                                       false,
		`name[givenName eq "Alice"]`:                                                            true,
	} {
		p, err := ParseFilter(f)
		if err != nil {
			t.Errorf("%s: %v", f, err)
			continue
		}
		if got := p.Match(m); got != want {
			t.Errorf("%s: %v, want %v", f, got, want)
		}
		if p.String() != f {
			t.Errorf("String() = %q", p.String())
		}
	}
}

func TestFilterRefusals(t *testing.T) {
	for _, f := range []string{
		``, `userName`, `userName eq`, `userName xx "a"`, `userName eq "a" and`, `(userName eq "a"`,
		`userName eq "a")`, `emails[type eq "work"`, `emails[type eq "work"]]`, `userName eq 'a'`,
		`userName eq "unterminated`, `userName eq "bad \x escape"`, `active gt true`, `title co null`,
		`loginCount co 4`, `1abc eq "a"`, `name.given.name eq "a"`, `emails[value[type eq "a"]]`,
		`name.givenName[x eq "a"]`, `not userName eq "a"`, `userName eq 0x10`, `urn:a:b: eq "x"`,
		`a eq "x" or`, `[a eq "b"]`, `userName eq NaN`, `userName pr extra`,
		strings.Repeat("(", 40) + `a pr` + strings.Repeat(")", 40),
		strings.Repeat("not (", 40) + `a pr` + strings.Repeat(")", 40),
		`a eq "` + strings.Repeat("x", MaxFilterBytes) + `"`,
	} {
		_, err := ParseFilter(f)
		var se *Error
		if !errors.As(err, &se) || se.Status != 400 || se.ScimType != "invalidFilter" {
			t.Errorf("%q: %v, want 400 invalidFilter", f, err)
		}
	}
}

func TestFilterEquality(t *testing.T) {
	for f, want := range map[string]string{
		`userName eq "bjensen"`:    "username=bjensen",
		`EXTERNALID eq "x"`:        "externalid=x",
		`userName eq "a" and a pr`: "",
		`name.givenName eq "a"`:    "",
		`userName ne "a"`:          "",
		`active eq true`:           "",
		`urn:ietf:params:scim:schemas:core:2.0:User:userName eq "u"`: "username=u",
	} {
		p, err := ParseFilter(f)
		if err != nil {
			t.Fatal(err)
		}
		a, v, ok := p.Equality()
		got := ""
		if ok {
			got = a + "=" + v
		}
		if got != want {
			t.Errorf("%s: %q, want %q", f, got, want)
		}
	}
}

// FuzzFilter: parsing never panics, and a parsed filter can be matched
// against a resource without panicking.
func FuzzFilter(f *testing.F) {
	for _, s := range []string{
		`userName eq "bjensen"`, `emails[type eq "work" and value co "@example.com"] or not (title pr)`,
		`meta.lastModified gt "2011-05-13T04:42:34Z"`, `urn:ietf:params:scim:schemas:core:2.0:User:name.familyName co "O'Malley"`,
		`loginCount ge 1e3`, `a eq null`, `((a pr))`, `members[value eq "x"]`,
	} {
		f.Add(s)
	}
	var m map[string]any
	_ = json.Unmarshal([]byte(alice), &m)
	f.Fuzz(func(t *testing.T, s string) {
		p, err := ParseFilter(s)
		if err != nil {
			var se *Error
			if !errors.As(err, &se) || se.ScimType != "invalidFilter" {
				t.Fatalf("%q: %v", s, err)
			}
			return
		}
		p.Match(m)
	})
}
