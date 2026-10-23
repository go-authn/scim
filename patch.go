package scim

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
)

// PATCH (RFC 7644 §3.5.2): a list of add, remove and replace operations,
// applied in order to the resource as a JSON object; all or nothing.
//
//	PATH = attrPath / valuePath [subAttr]
//
// Besides the RFC, two shapes identity providers really send are accepted:
// an operation name in any case ("Replace", Entra ID), and a remove on a
// multi-valued attribute with a value listing the elements to remove by
// their "value" (Entra ID, for group members). An add whose path filters a
// multi-valued attribute by equality and matches nothing creates the
// element (emails[type eq "work"].value, Entra ID).

// PatchOp is one operation.
type PatchOp struct {
	Op    string          `json:"op"`
	Path  string          `json:"path,omitempty"`
	Value json.RawMessage `json:"value,omitempty"`
}

// PatchRequest is a PATCH body.
type PatchRequest struct {
	Schemas    []string  `json:"schemas"`
	Operations []PatchOp `json:"Operations"`
}

type patchPath struct {
	path   attrPath
	filter node // nil when the path has no value filter
	sub    string
	raw    string
}

func parsePatchPath(s string) (patchPath, *Error) {
	pp := patchPath{raw: s}
	if len(s) > MaxFilterBytes {
		return pp, badRequest("invalidPath", "path longer than %d bytes", MaxFilterBytes)
	}
	head, rest, hasFilter := strings.Cut(s, "[")
	if !hasFilter {
		p, err := parseAttrPath(s)
		if err != nil {
			return pp, badRequest("invalidPath", "invalid path %q", s)
		}
		pp.path = p
		return pp, nil
	}
	p, err := parseAttrPath(head)
	if err != nil || p.sub != "" {
		return pp, badRequest("invalidPath", "invalid path %q", s)
	}
	end := strings.LastIndexByte(rest, ']')
	if end < 0 {
		return pp, badRequest("invalidPath", "invalid path %q", s)
	}
	inner, after := rest[:end], rest[end+1:]
	if after != "" {
		sub, ok := strings.CutPrefix(after, ".")
		if !ok || !validName(sub) {
			return pp, badRequest("invalidPath", "invalid path %q", s)
		}
		pp.sub = sub
	}
	toks, lerr := lex(inner)
	if lerr != nil {
		return pp, badRequest("invalidPath", "invalid filter in path %q", s)
	}
	ps := &parser{toks: toks}
	f, ferr := ps.or(true)
	if ferr != nil || ps.pos != len(ps.toks) {
		return pp, badRequest("invalidPath", "invalid filter in path %q", s)
	}
	pp.path, pp.filter = p, f
	return pp, nil
}

// applyPatch applies ops to res. readOnly names the top-level attributes
// (lower-case) that cannot be written.
func applyPatch(res map[string]any, ops []PatchOp, readOnly map[string]bool) *Error {
	for i, op := range ops {
		kind := strings.ToLower(op.Op)
		if kind != "add" && kind != "remove" && kind != "replace" {
			return badRequest("invalidSyntax", "operation %d: op %q: want add, remove or replace", i, op.Op)
		}
		var value any
		if len(bytes.TrimSpace(op.Value)) > 0 {
			if err := json.Unmarshal(op.Value, &value); err != nil {
				return badRequest("invalidSyntax", "operation %d: invalid value", i)
			}
		}
		if op.Path == "" {
			if kind == "remove" {
				return badRequest("noTarget", "operation %d: remove needs a path", i)
			}
			obj, ok := value.(map[string]any)
			if !ok {
				return badRequest("invalidValue", "operation %d: without a path, the value must be an object", i)
			}
			for k, v := range obj {
				if strings.EqualFold(k, "schemas") {
					continue
				}
				pp, err := parsePatchPath(k)
				if err != nil {
					return err
				}
				if err := applyOne(res, kind, pp, v, true, readOnly); err != nil {
					return err
				}
			}
			continue
		}
		pp, err := parsePatchPath(op.Path)
		if err != nil {
			return err
		}
		if err := applyOne(res, kind, pp, value, value != nil, readOnly); err != nil {
			return err
		}
	}
	return nil
}

// key returns the existing spelling of name in m, or name.
func key(m map[string]any, name string) string {
	if _, ok := m[name]; ok {
		return name
	}
	for k := range m {
		if strings.EqualFold(k, name) {
			return k
		}
	}
	return name
}

func applyOne(res map[string]any, kind string, pp patchPath, v any, hasValue bool, readOnly map[string]bool) *Error {
	if pp.path.urn == "" && readOnly[pp.path.attr] {
		// Okta repeats the id in a replace without a path: writing the value
		// an attribute already has changes nothing and is let through.
		if kind == "replace" && pp.filter == nil && pp.path.sub == "" && reflect.DeepEqual(lookup(res, pp.path.attr), v) {
			return nil
		}
		return badRequest("mutability", "%s is read-only", pp.path.attr)
	}
	if kind != "remove" && !hasValue {
		return badRequest("invalidValue", "%s needs a value", kind)
	}
	base := res
	if pp.path.urn != "" {
		k := key(res, pp.path.urn)
		ext, ok := res[k].(map[string]any)
		if !ok {
			if kind == "remove" {
				return nil
			}
			ext = map[string]any{}
			res[k] = ext
		}
		base = ext
	}
	k := key(base, pp.path.rawAttr)
	cur := base[k]

	if pp.filter != nil {
		return applyFiltered(base, k, cur, kind, pp, v)
	}
	if pp.path.sub != "" {
		switch c := cur.(type) {
		case map[string]any:
			setSub(c, kind, pp.path.rawSub, v)
		case []any: // every element (no filter)
			for _, e := range c {
				if em, ok := e.(map[string]any); ok {
					setSub(em, kind, pp.path.rawSub, v)
				}
			}
		case nil:
			if kind != "remove" {
				base[k] = map[string]any{pp.path.rawSub: v}
			}
		default:
			return badRequest("invalidPath", "%s has no sub-attributes", pp.path.attr)
		}
		return nil
	}
	switch kind {
	case "remove":
		if arr, ok := cur.([]any); ok && hasValue {
			// Remove the listed elements, by their "value".
			drop := map[string]bool{}
			list, isList := v.([]any)
			if !isList {
				list = []any{v}
			}
			for _, e := range list {
				if em, ok := e.(map[string]any); ok {
					if s, ok := lookup(em, "value").(string); ok {
						drop[s] = true
					}
				}
			}
			kept := arr[:0:0]
			for _, e := range arr {
				if em, ok := e.(map[string]any); ok {
					if s, ok := lookup(em, "value").(string); ok && drop[s] {
						continue
					}
				}
				kept = append(kept, e)
			}
			setOrDelete(base, k, kept)
			return nil
		}
		delete(base, k)
	case "add":
		switch c := cur.(type) {
		case []any:
			add, isList := v.([]any)
			if !isList {
				add = []any{v}
			}
			// Duplicates are skipped in linear time: a quadratic scan of
			// ten thousand members is a request that costs seconds.
			seen := make(map[string]bool, len(c)+len(add))
			for _, e := range c {
				seen[canonical(e)] = true
			}
			for _, e := range add {
				if s := canonical(e); !seen[s] {
					seen[s] = true
					c = append(c, e)
				}
			}
			base[k] = c
		case map[string]any:
			if vm, ok := v.(map[string]any); ok {
				for sk, sv := range vm {
					c[key(c, sk)] = sv
				}
				return nil
			}
			base[k] = v
		default:
			base[k] = v
		}
	case "replace":
		base[k] = v
	}
	return nil
}

func setSub(m map[string]any, kind, sub string, v any) {
	k := key(m, sub)
	if kind == "remove" {
		delete(m, k)
		return
	}
	m[k] = v
}

func setOrDelete(m map[string]any, k string, arr []any) {
	if len(arr) == 0 {
		delete(m, k)
		return
	}
	m[k] = arr
}

// canonical is a value's JSON (encoding/json sorts object keys).
func canonical(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func applyFiltered(base map[string]any, k string, cur any, kind string, pp patchPath, v any) *Error {
	arr, _ := cur.([]any)
	var hits []int
	for i, e := range arr {
		if em, ok := e.(map[string]any); ok && pp.filter.match(em) {
			hits = append(hits, i)
		}
	}
	if len(hits) == 0 {
		if kind == "add" && pp.sub != "" {
			if elem, ok := equalities(pp.filter); ok {
				elem[pp.sub] = v
				base[k] = append(arr, elem)
				return nil
			}
		}
		return badRequest("noTarget", "%s matches nothing", pp.raw)
	}
	switch {
	case pp.sub != "":
		for _, i := range hits {
			setSub(arr[i].(map[string]any), kind, pp.sub, v)
		}
	case kind == "remove":
		kept := arr[:0:0]
		j := 0
		for i, e := range arr {
			if j < len(hits) && hits[j] == i {
				j++
				continue
			}
			kept = append(kept, e)
		}
		setOrDelete(base, k, kept)
	case kind == "replace":
		for _, i := range hits {
			arr[i] = v
		}
	default:
		return badRequest("invalidPath", "add to %s needs a sub-attribute", pp.raw)
	}
	return nil
}

// equalities turns `a eq "x" and b eq "y"` into {a: x, b: y}.
func equalities(n node) (map[string]any, bool) {
	switch x := n.(type) {
	case *compare:
		if x.op != "eq" || x.path.sub != "" || x.path.urn != "" || x.value == nil {
			return nil, false
		}
		return map[string]any{x.path.rawAttr: x.value}, true
	case *logical:
		if !x.and {
			return nil, false
		}
		l, ok1 := equalities(x.l)
		r, ok2 := equalities(x.r)
		if !ok1 || !ok2 {
			return nil, false
		}
		for k, v := range r {
			l[k] = v
		}
		return l, true
	}
	return nil, false
}
