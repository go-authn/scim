package scim

import (
	"encoding/json"
	"errors"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

func ops(t testing.TB, s string) []PatchOp {
	t.Helper()
	var o []PatchOp
	if err := json.Unmarshal([]byte(s), &o); err != nil {
		t.Fatal(err)
	}
	return o
}

func TestApplyPatch(t *testing.T) {
	const base = `{"id":"1","userName":"u","name":{"givenName":"A"},
	  "emails":[{"value":"a@x","type":"work"},{"value":"b@x","type":"home"}],
	  "urn:ext:2.0:User":{"dept":"d"}}`
	ro := map[string]bool{"id": true, "meta": true}
	for _, tc := range []struct{ name, ops, want string }{
		{"add merges a complex attribute", `[{"op":"add","path":"name","value":{"familyName":"B"}}]`,
			`{"id":"1","userName":"u","name":{"givenName":"A","familyName":"B"},"emails":[{"value":"a@x","type":"work"},{"value":"b@x","type":"home"}],"urn:ext:2.0:User":{"dept":"d"}}`},
		{"add appends, without duplicates", `[{"op":"add","path":"emails","value":[{"value":"a@x","type":"work"},{"value":"c@x"}]}]`,
			`{"id":"1","userName":"u","name":{"givenName":"A"},"emails":[{"value":"a@x","type":"work"},{"value":"b@x","type":"home"},{"value":"c@x"}],"urn:ext:2.0:User":{"dept":"d"}}`},
		{"add a single value to a list", `[{"op":"add","path":"emails","value":{"value":"c@x"}}]`,
			`{"id":"1","userName":"u","name":{"givenName":"A"},"emails":[{"value":"a@x","type":"work"},{"value":"b@x","type":"home"},{"value":"c@x"}],"urn:ext:2.0:User":{"dept":"d"}}`},
		{"replace a filtered element", `[{"op":"replace","path":"emails[type eq \"home\"]","value":{"value":"h@x","type":"home"}}]`,
			`{"id":"1","userName":"u","name":{"givenName":"A"},"emails":[{"value":"a@x","type":"work"},{"value":"h@x","type":"home"}],"urn:ext:2.0:User":{"dept":"d"}}`},
		{"remove a filtered element", `[{"op":"remove","path":"emails[value eq \"a@x\"]"}]`,
			`{"id":"1","userName":"u","name":{"givenName":"A"},"emails":[{"value":"b@x","type":"home"}],"urn:ext:2.0:User":{"dept":"d"}}`},
		{"remove every element", `[{"op":"remove","path":"emails[type pr]"}]`,
			`{"id":"1","userName":"u","name":{"givenName":"A"},"urn:ext:2.0:User":{"dept":"d"}}`},
		{"remove a sub-attribute of every element", `[{"op":"remove","path":"emails.type"}]`,
			`{"id":"1","userName":"u","name":{"givenName":"A"},"emails":[{"value":"a@x"},{"value":"b@x"}],"urn:ext:2.0:User":{"dept":"d"}}`},
		{"remove a filtered sub-attribute", `[{"op":"remove","path":"emails[type eq \"work\"].type"}]`,
			`{"id":"1","userName":"u","name":{"givenName":"A"},"emails":[{"value":"a@x"},{"value":"b@x","type":"home"}],"urn:ext:2.0:User":{"dept":"d"}}`},
		{"remove an attribute; a missing one is no error", `[{"op":"remove","path":"name"},{"op":"remove","path":"title"},{"op":"remove","path":"urn:other:x"}]`,
			`{"id":"1","userName":"u","emails":[{"value":"a@x","type":"work"},{"value":"b@x","type":"home"}],"urn:ext:2.0:User":{"dept":"d"}}`},
		{"extension attribute, names without case", `[{"op":"replace","path":"urn:ext:2.0:User:DEPT","value":"e"},{"op":"add","path":"urn:new:1:x","value":"y"},{"op":"replace","path":"USERNAME","value":"v"}]`,
			`{"id":"1","userName":"v","name":{"givenName":"A"},"emails":[{"value":"a@x","type":"work"},{"value":"b@x","type":"home"}],"urn:ext:2.0:User":{"dept":"e"},"urn:new:1":{"x":"y"}}`},
		{"no path, dotted keys", `[{"op":"replace","value":{"name.familyName":"F","displayName":"D","schemas":["ignored"]}}]`,
			`{"id":"1","userName":"u","name":{"givenName":"A","familyName":"F"},"displayName":"D","emails":[{"value":"a@x","type":"work"},{"value":"b@x","type":"home"}],"urn:ext:2.0:User":{"dept":"d"}}`},
		{"add a sub-attribute to a missing complex", `[{"op":"add","path":"address.city","value":"Paris"}]`,
			`{"id":"1","userName":"u","name":{"givenName":"A"},"address":{"city":"Paris"},"emails":[{"value":"a@x","type":"work"},{"value":"b@x","type":"home"}],"urn:ext:2.0:User":{"dept":"d"}}`},
		{"filtered add creating an element", `[{"op":"add","path":"emails[type eq \"other\" and primary eq false].value","value":"o@x"}]`,
			`{"id":"1","userName":"u","name":{"givenName":"A"},"emails":[{"value":"a@x","type":"work"},{"value":"b@x","type":"home"},{"type":"other","primary":false,"value":"o@x"}],"urn:ext:2.0:User":{"dept":"d"}}`},
		{"replace the same id", `[{"op":"replace","path":"id","value":"1"}]`, base},
	} {
		m := asMap(t, base)
		if err := applyPatch(m, ops(t, tc.ops), ro); err != nil {
			t.Errorf("%s: %v", tc.name, err)
			continue
		}
		if want := asMap(t, tc.want); !reflect.DeepEqual(m, want) {
			got, _ := json.Marshal(m)
			t.Errorf("%s:\n got %s\nwant %s", tc.name, got, tc.want)
		}
	}
	for _, tc := range []struct{ name, ops, scimType string }{
		{"add to a filtered element without sub", `[{"op":"add","path":"emails[type eq \"work\"]","value":{"x":1}}]`, "invalidPath"},
		{"filtered add that cannot create", `[{"op":"add","path":"emails[type ne \"work\"].value","value":"x"}]`, ""},
		{"sub of a scalar", `[{"op":"replace","path":"userName.x","value":"y"}]`, "invalidPath"},
		{"filter after sub", `[{"op":"replace","path":"name.x[a eq \"b\"]","value":"y"}]`, "invalidPath"},
		{"garbage after filter", `[{"op":"replace","path":"emails[type eq \"work\"]x","value":"y"}]`, "invalidPath"},
		{"bad sub after filter", `[{"op":"replace","path":"emails[type eq \"work\"].1x","value":"y"}]`, "invalidPath"},
		{"invalid value json", `[{"op":"replace","path":"a","value":"x"}]`, ""},
		{"read-only urn path allowed", `[{"op":"replace","path":"id","value":"2"}]`, "mutability"},
		{"long path", `[{"op":"replace","path":"` + strings.Repeat("a", MaxFilterBytes+1) + `","value":1}]`, "invalidPath"},
		{"no-path key that is no path", `[{"op":"add","value":{"1x":1}}]`, "invalidPath"},
	} {
		m := asMap(t, base)
		o := ops(t, tc.ops)
		if tc.name == "invalid value json" {
			o[0].Value = json.RawMessage(`{`)
			tc.scimType = "invalidSyntax"
		}
		err := applyPatch(m, o, ro)
		var se *Error
		if !errors.As(err, &se) {
			t.Errorf("%s: applied", tc.name)
			continue
		}
		if tc.scimType != "" && se.ScimType != tc.scimType {
			t.Errorf("%s: %s, want %s", tc.name, se.ScimType, tc.scimType)
		}
	}
}

// FuzzPatch: arbitrary operations never panic, and either apply or are
// refused with a 400.
func FuzzPatch(f *testing.F) {
	for _, s := range []string{
		`[{"op":"Replace","path":"emails[type eq \"work\"].value","value":"x"}]`,
		`[{"op":"remove","path":"members[value eq \"1\"]"}]`,
		`[{"op":"add","value":{"name.givenName":"g","active":"False"}}]`,
		`[{"op":"remove","path":"members","value":[{"value":"1"}]}]`,
		`[{"op":"add","path":"urn:ext:x:y.z","value":{"a":[1,2]}}]`,
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		var o []PatchOp
		if json.Unmarshal([]byte(s), &o) != nil || len(o) > 64 {
			return
		}
		m := map[string]any{}
		_ = json.Unmarshal([]byte(alice), &m)
		if err := applyPatch(m, o, map[string]bool{"id": true}); err != nil && err.Status != 400 {
			t.Fatalf("%s: %v", s, err)
		}
		if _, err := json.Marshal(m); err != nil {
			t.Fatalf("%s: result is not JSON: %v", s, err)
		}
	})
}

// FuzzServer: arbitrary request bodies on every endpoint never panic and
// never answer 500 with the Memory backend.
func FuzzServer(f *testing.F) {
	f.Add("POST", "/Users", `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"a","emails":[{"value":"x","primary":true}]}`)
	f.Add("POST", "/Groups", `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"g","members":[{"value":"id-001"}]}`)
	f.Add("PATCH", "/Users/id-001", `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"active","value":"False"}]}`)
	f.Add("PUT", "/Groups/id-002", `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"h"}`)
	f.Add("GET", "/Users?filter=userName%20eq%20%22a%22&attributes=userName", "")
	f.Add("POST", "/Groups/.search", `{"filter":"members[value eq \"id-001\"]","count":1}`)
	f.Fuzz(func(t *testing.T, method, target, body string) {
		if !strings.HasPrefix(target, "/") || strings.ContainsAny(target, " \r\n\t#") || len(target) > 2048 {
			return
		}
		c, _ := newClient(t)
		c.want(201, "POST", "/Users", `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"seed"}`)
		c.want(201, "POST", "/Groups", `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"g","members":[{"value":"id-001"}]}`)
		r := httptest.NewRequest("GET", "/", strings.NewReader(body))
		r.Method = method
		u := r.URL
		if pu, err := u.Parse(target); err == nil {
			r.URL = pu
		} else {
			return
		}
		r.Header.Set("Authorization", "Bearer "+c.token)
		w := httptest.NewRecorder()
		c.h.ServeHTTP(w, r)
		if w.Code >= 500 {
			t.Fatalf("%s %s %q: %d %s", method, target, body, w.Code, w.Body)
		}
	})
}
