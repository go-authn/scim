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
func toMap(v any) (map[string]any, error) {
	switch r := v.(type) {
	case *User:
		return userMap(r), nil
	case *Group:
		return groupMap(r), nil
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

func userMap(u *User) map[string]any {
	m := make(map[string]any, 11)
	m["schemas"] = strList(u.Schemas)
	m["id"] = u.ID
	putStr(m, "externalId", u.ExternalID)
	m["userName"] = u.UserName
	if u.Name != nil {
		n := make(map[string]any, 6)
		putStr(n, "formatted", u.Name.Formatted)
		putStr(n, "familyName", u.Name.FamilyName)
		putStr(n, "givenName", u.Name.GivenName)
		putStr(n, "middleName", u.Name.MiddleName)
		putStr(n, "honorificPrefix", u.Name.HonorificPrefix)
		putStr(n, "honorificSuffix", u.Name.HonorificSuffix)
		m["name"] = n
	}
	putStr(m, "displayName", u.DisplayName)
	if u.Active != nil {
		m["active"] = bool(*u.Active)
	}
	if len(u.Emails) > 0 {
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
	if len(u.Groups) > 0 {
		m["groups"] = refList(u.Groups)
	}
	m["meta"] = metaMap(&u.Meta)
	return m
}

func groupMap(g *Group) map[string]any {
	m := make(map[string]any, 6)
	m["schemas"] = strList(g.Schemas)
	m["id"] = g.ID
	putStr(m, "externalId", g.ExternalID)
	m["displayName"] = g.DisplayName
	if len(g.Members) > 0 {
		m["members"] = refList(g.Members)
	}
	m["meta"] = metaMap(&g.Meta)
	return m
}
