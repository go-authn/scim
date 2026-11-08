package scim

import (
	"bytes"
	"encoding/json"
	"time"
)

// toMap returns a User or a Group as the JSON object a client sees, which is
// what filters, PATCH and attribute selection work on. For the two types of
// this package it builds the object directly; building it through
// json.Marshal and json.Decode costs eighty allocations per user, paid for
// every user a list request has to examine. TestToMapMatchesJSON keeps the
// two paths identical.
func toMap(v any) (map[string]any, error) { return toMapSel(v, nil) }

// attrSel names the top-level attributes a map is built with, lower-cased;
// nil means all of them.
type attrSel map[string]bool

func (s attrSel) has(lower string) bool { return s == nil || s[lower] }

// toMapSel is toMap restricted to the top-level attributes in sel. A filter
// reads only the attributes it names (Filter.attrs), so matching it against
// the restricted map gives the answer it gives on the whole one, without
// building what it never looks at (TestFilterOnSelectedMap). The restricted
// map is for matching only: a response is built from toMap.
func toMapSel(v any, sel attrSel) (map[string]any, error) {
	switch r := v.(type) {
	case *User:
		return userMap(r, sel), nil
	case *Group:
		return groupMap(r, sel), nil
	}
	return jsonMap(v)
}

// jsonMap is the reference: marshal, then decode.
func jsonMap(v any) (map[string]any, error) {
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

func putStr(m map[string]any, k, v string) {
	if v != "" {
		m[k] = v
	}
}

func strList(s []string) any {
	if s == nil {
		return nil
	}
	out := make([]any, len(s))
	for i, x := range s {
		out[i] = x
	}
	return out
}

func metaMap(x *Meta) map[string]any {
	m := make(map[string]any, 5)
	m["resourceType"] = x.ResourceType
	m["created"] = x.Created.Format(time.RFC3339Nano)
	m["lastModified"] = x.LastModified.Format(time.RFC3339Nano)
	putStr(m, "location", x.Location)
	putStr(m, "version", x.Version)
	return m
}

func refList(refs []Ref) []any {
	out := make([]any, len(refs))
	for i, r := range refs {
		e := make(map[string]any, 4)
		e["value"] = r.Value
		putStr(e, "$ref", r.Ref)
		putStr(e, "display", r.Display)
		putStr(e, "type", r.Type)
		out[i] = e
	}
	return out
}

func mapFor(sel attrSel, full int) map[string]any {
	if sel == nil {
		return make(map[string]any, full)
	}
	return make(map[string]any, min(len(sel), full))
}

func userMap(u *User, sel attrSel) map[string]any {
	m := mapFor(sel, 11)
	if sel.has("schemas") {
		m["schemas"] = strList(u.Schemas)
	}
	if sel.has("id") {
		m["id"] = u.ID
	}
	if sel.has("externalid") {
		putStr(m, "externalId", u.ExternalID)
	}
	if sel.has("username") {
		m["userName"] = u.UserName
	}
	if u.Name != nil && sel.has("name") {
		n := make(map[string]any, 6)
		putStr(n, "formatted", u.Name.Formatted)
		putStr(n, "familyName", u.Name.FamilyName)
		putStr(n, "givenName", u.Name.GivenName)
		putStr(n, "middleName", u.Name.MiddleName)
		putStr(n, "honorificPrefix", u.Name.HonorificPrefix)
		putStr(n, "honorificSuffix", u.Name.HonorificSuffix)
		m["name"] = n
	}
	if sel.has("displayname") {
		putStr(m, "displayName", u.DisplayName)
	}
	if u.Active != nil && sel.has("active") {
		m["active"] = bool(*u.Active)
	}
	if len(u.Emails) > 0 && sel.has("emails") {
		es := make([]any, len(u.Emails))
		for i, e := range u.Emails {
			em := make(map[string]any, 4)
			em["value"] = e.Value
			putStr(em, "type", e.Type)
			putStr(em, "display", e.Display)
			if e.Primary {
				em["primary"] = true
			}
			es[i] = em
		}
		m["emails"] = es
	}
	if len(u.Groups) > 0 && sel.has("groups") {
		m["groups"] = refList(u.Groups)
	}
	if sel.has("meta") {
		m["meta"] = metaMap(&u.Meta)
	}
	return m
}

func groupMap(g *Group, sel attrSel) map[string]any {
	m := mapFor(sel, 6)
	if sel.has("schemas") {
		m["schemas"] = strList(g.Schemas)
	}
	if sel.has("id") {
		m["id"] = g.ID
	}
	if sel.has("externalid") {
		putStr(m, "externalId", g.ExternalID)
	}
	if sel.has("displayname") {
		m["displayName"] = g.DisplayName
	}
	if len(g.Members) > 0 && sel.has("members") {
		m["members"] = refList(g.Members)
	}
	if sel.has("meta") {
		m["meta"] = metaMap(&g.Meta)
	}
	return m
}
