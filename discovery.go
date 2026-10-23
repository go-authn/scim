package scim

import (
	"net/http"
)

// Discovery endpoints (RFC 7644 §4): what this service provider supports,
// its resource types and the schemas of the attributes it models.

type attr struct {
	Name          string `json:"name"`
	Type          string `json:"type"`
	MultiValued   bool   `json:"multiValued"`
	Required      bool   `json:"required"`
	CaseExact     bool   `json:"caseExact"`
	Mutability    string `json:"mutability"`
	Returned      string `json:"returned"`
	Uniqueness    string `json:"uniqueness"`
	SubAttributes []attr `json:"subAttributes,omitempty"`
}

func str(name string, required, caseExact bool, uniqueness string) attr {
	return attr{Name: name, Type: "string", Required: required, CaseExact: caseExact, Mutability: "readWrite", Returned: "default", Uniqueness: uniqueness}
}

func refAttrs(mutability string) []attr {
	v := str("value", false, true, "none")
	r := attr{Name: "$ref", Type: "reference", CaseExact: true, Mutability: mutability, Returned: "default", Uniqueness: "none"}
	d := str("display", false, false, "none")
	d.Mutability = "readOnly"
	t := str("type", false, false, "none")
	t.Mutability = "readOnly"
	if mutability != "readWrite" {
		v.Mutability = mutability
	} else {
		v.Mutability = "immutable"
	}
	return []attr{v, r, d, t}
}

var userAttrs = []attr{
	str("userName", true, false, "server"),
	{Name: "name", Type: "complex", Mutability: "readWrite", Returned: "default", Uniqueness: "none", SubAttributes: []attr{
		str("formatted", false, false, "none"), str("familyName", false, false, "none"), str("givenName", false, false, "none"),
		str("middleName", false, false, "none"), str("honorificPrefix", false, false, "none"), str("honorificSuffix", false, false, "none"),
	}},
	str("displayName", false, false, "none"),
	{Name: "active", Type: "boolean", Mutability: "readWrite", Returned: "default", Uniqueness: "none"},
	{Name: "emails", Type: "complex", MultiValued: true, Mutability: "readWrite", Returned: "default", Uniqueness: "none", SubAttributes: []attr{
		str("value", false, false, "none"), str("type", false, false, "none"), str("display", false, false, "none"),
		{Name: "primary", Type: "boolean", Mutability: "readWrite", Returned: "default", Uniqueness: "none"},
	}},
	{Name: "groups", Type: "complex", MultiValued: true, Mutability: "readOnly", Returned: "default", Uniqueness: "none", SubAttributes: refAttrs("readOnly")},
}

var groupAttrs = []attr{
	str("displayName", true, false, "none"),
	{Name: "members", Type: "complex", MultiValued: true, Mutability: "readWrite", Returned: "default", Uniqueness: "none", SubAttributes: refAttrs("readWrite")},
}

func (s *Server) schemaDoc(rt resourceType) map[string]any {
	attrs := userAttrs
	desc := "User Account"
	if rt == resourceGroup {
		attrs, desc = groupAttrs, "Group"
	}
	return map[string]any{
		"schemas": []string{SchemaSchema}, "id": rt.schema(), "name": rt.name(), "description": desc, "attributes": attrs,
		"meta": map[string]any{"resourceType": "Schema", "location": s.BaseURL + "/Schemas/" + rt.schema()},
	}
}

func (s *Server) resourceTypeDoc(rt resourceType) map[string]any {
	return map[string]any{
		"schemas": []string{ResourceTypeSc}, "id": rt.name(), "name": rt.name(), "endpoint": rt.endpoint(),
		"description": rt.name() + "s", "schema": rt.schema(),
		"meta": map[string]any{"resourceType": "ResourceType", "location": s.BaseURL + "/ResourceTypes/" + rt.name()},
	}
}

func listOf(items ...map[string]any) listResponse {
	return listResponse{Schemas: []string{ListResponse}, TotalResults: len(items), StartIndex: 1, ItemsPerPage: len(items), Resources: items}
}

func (s *Server) discovery(w http.ResponseWriter, what, id string) {
	notFound := &Error{Status: http.StatusNotFound, Detail: "no such " + what}
	switch what {
	case "ServiceProviderConfig":
		if id != "" {
			writeError(w, notFound)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"schemas":          []string{SPConfigSchema},
			"documentationUri": "https://github.com/go-authn/scim",
			"patch":            map[string]any{"supported": true},
			"bulk":             map[string]any{"supported": false, "maxOperations": 0, "maxPayloadSize": 0},
			"filter":           map[string]any{"supported": true, "maxResults": s.maxResults()},
			"changePassword":   map[string]any{"supported": false},
			"sort":             map[string]any{"supported": false},
			"etag":             map[string]any{"supported": true},
			"authenticationSchemes": []map[string]any{{
				"type": "oauthbearertoken", "name": "OAuth Bearer Token", "description": "Authentication with a bearer token",
			}},
			"meta": map[string]any{"resourceType": "ServiceProviderConfig", "location": s.BaseURL + "/ServiceProviderConfig"},
		})
	case "ResourceTypes":
		switch id {
		case "":
			writeJSON(w, http.StatusOK, listOf(s.resourceTypeDoc(resourceUser), s.resourceTypeDoc(resourceGroup)))
		case "User":
			writeJSON(w, http.StatusOK, s.resourceTypeDoc(resourceUser))
		case "Group":
			writeJSON(w, http.StatusOK, s.resourceTypeDoc(resourceGroup))
		default:
			writeError(w, notFound)
		}
	case "Schemas":
		switch id {
		case "":
			writeJSON(w, http.StatusOK, listOf(s.schemaDoc(resourceUser), s.schemaDoc(resourceGroup)))
		case UserSchema:
			writeJSON(w, http.StatusOK, s.schemaDoc(resourceUser))
		case GroupSchema:
			writeJSON(w, http.StatusOK, s.schemaDoc(resourceGroup))
		default:
			writeError(w, notFound)
		}
	}
}
