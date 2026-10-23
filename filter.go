package scim

import (
	"encoding/json"
	"strconv"
	"strings"
)

// Filters (RFC 7644 §3.4.2.2):
//
//	FILTER    = attrExp / logExp / valuePath / *1"not" "(" FILTER ")"
//	valuePath = attrPath "[" valFilter "]"
//	attrExp   = (attrPath SP "pr") / (attrPath SP compareOp SP compValue)
//	logExp    = FILTER SP ("and" / "or") SP FILTER
//	compareOp = "eq" / "ne" / "co" / "sw" / "ew" / "gt" / "lt" / "ge" / "le"
//	attrPath  = [URI ":"] ATTRNAME *1subAttr
//
// "not" binds tighter than "and", which binds tighter than "or". Attribute
// names and operators are case-insensitive; string values compare without
// case except for the attributes that are caseExact in RFC 7643 (id,
// externalId, $ref, meta.version and the value of a member or group
// reference). A multi-valued attribute matches when any of its values does,
// and a complex multi-valued attribute named without a sub-attribute is
// compared through its "value" (RFC 7644 §3.4.2.2).

// MaxFilterBytes bounds the length of a filter.
const MaxFilterBytes = 4096

const maxFilterDepth = 32

// Filter is a parsed filter.
type Filter struct {
	root node
	src  string
}

// String returns the filter as it was written.
func (f *Filter) String() string { return f.src }

// Match reports whether a resource, as a JSON object, matches.
func (f *Filter) Match(resource map[string]any) bool { return f.root.match(resource) }

// Equality reports whether the filter is a single `attr eq "value"` on a
// top-level attribute, so that a Backend can answer it from an index
// (userName, externalId, displayName). attr is lower-cased.
func (f *Filter) Equality() (attr, value string, ok bool) {
	c, isCmp := f.root.(*compare)
	if !isCmp || c.op != "eq" || c.path.urn != "" || c.path.sub != "" {
		return "", "", false
	}
	s, isStr := c.value.(string)
	if !isStr {
		return "", "", false
	}
	return c.path.attr, s, true
}

type node interface{ match(map[string]any) bool }

type attrPath struct {
	urn  string // "" for the core schema of the resource
	attr string // lower-cased
	sub  string // lower-cased, may be ""
	// rawAttr and rawSub keep the spelling, for creating attributes.
	rawAttr, rawSub string
}

type logical struct {
	and  bool
	l, r node
}

type negation struct{ x node }

type present struct{ path attrPath }

type compare struct {
	path  attrPath
	op    string
	value any // string, float64, bool or nil
}

type valueFilter struct {
	path   attrPath
	filter node
}

func (n *logical) match(m map[string]any) bool {
	if n.and {
		return n.l.match(m) && n.r.match(m)
	}
	return n.l.match(m) || n.r.match(m)
}

func (n *negation) match(m map[string]any) bool { return !n.x.match(m) }

func (n *present) match(m map[string]any) bool {
	for _, v := range values(m, n.path) {
		if !empty(v) {
			return true
		}
	}
	return false
}

func (n *compare) match(m map[string]any) bool {
	vs := values(m, n.path)
	if n.value == nil {
		found := false
		for _, v := range vs {
			if !empty(v) {
				found = true
			}
		}
		return found == (n.op == "ne")
	}
	if n.op == "ne" {
		for _, v := range vs {
			if compareOne(v, "eq", n.value, caseExact(n.path)) {
				return false
			}
		}
		return true
	}
	for _, v := range vs {
		if compareOne(v, n.op, n.value, caseExact(n.path)) {
			return true
		}
	}
	return false
}

func (n *valueFilter) match(m map[string]any) bool {
	base := m
	if n.path.urn != "" {
		ext, ok := lookup(m, n.path.urn).(map[string]any)
		if !ok {
			return false
		}
		base = ext
	}
	switch v := lookup(base, n.path.attr).(type) {
	case []any:
		for _, e := range v {
			if em, ok := e.(map[string]any); ok && n.filter.match(em) {
				return true
			}
		}
	case map[string]any:
		return n.filter.match(v)
	}
	return false
}

// lookup finds a key without regard to case (RFC 7643 §2.1).
func lookup(m map[string]any, key string) any {
	if v, ok := m[key]; ok {
		return v
	}
	for k, v := range m {
		if strings.EqualFold(k, key) {
			return v
		}
	}
	return nil
}

// values lists what a path names in a resource.
func values(m map[string]any, p attrPath) []any {
	base := m
	if p.urn != "" {
		ext, ok := lookup(m, p.urn).(map[string]any)
		if !ok {
			return nil
		}
		base = ext
	}
	v := lookup(base, p.attr)
	sub := p.sub
	var out []any
	add := func(e any) {
		if em, ok := e.(map[string]any); ok {
			if sub == "" {
				sub2 := lookup(em, "value")
				out = append(out, sub2)
				return
			}
			out = append(out, lookup(em, sub))
			return
		}
		if sub == "" {
			out = append(out, e)
		}
	}
	if arr, ok := v.([]any); ok {
		for _, e := range arr {
			add(e)
		}
		return out
	}
	if em, ok := v.(map[string]any); ok && sub != "" {
		return []any{lookup(em, sub)}
	}
	if sub != "" {
		return nil
	}
	return []any{v}
}

func empty(v any) bool {
	switch x := v.(type) {
	case nil:
		return true
	case string:
		return x == ""
	case []any:
		return len(x) == 0
	case map[string]any:
		return len(x) == 0
	}
	return false
}

func caseExact(p attrPath) bool {
	switch p.attr {
	case "id", "externalid", "$ref":
		return p.sub == ""
	case "meta":
		return p.sub == "version"
	case "members", "groups":
		return p.sub == "" || p.sub == "value" || p.sub == "$ref"
	}
	return p.sub == "$ref"
}

func compareOne(v any, op string, want any, exact bool) bool {
	switch w := want.(type) {
	case string:
		s, ok := v.(string)
		if !ok {
			return false
		}
		if !exact {
			s, w = strings.ToLower(s), strings.ToLower(w)
		}
		switch op {
		case "eq":
			return s == w
		case "co":
			return strings.Contains(s, w)
		case "sw":
			return strings.HasPrefix(s, w)
		case "ew":
			return strings.HasSuffix(s, w)
		case "gt":
			return s > w
		case "ge":
			return s >= w
		case "lt":
			return s < w
		case "le":
			return s <= w
		}
	case float64:
		n, ok := v.(float64)
		if !ok {
			return false
		}
		switch op {
		case "eq":
			return n == w
		case "gt":
			return n > w
		case "ge":
			return n >= w
		case "lt":
			return n < w
		case "le":
			return n <= w
		}
	case bool:
		b, ok := v.(bool)
		return ok && op == "eq" && b == w
	}
	return false
}

// ---- parsing ----

type token struct {
	kind byte // '(' ')' '[' ']' 's' (string) 'w' (word)
	text string
	str  string // decoded string for 's'
}

func lex(src string) ([]token, error) {
	var out []token
	for i := 0; i < len(src); {
		c := src[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			i++
		case c == '(' || c == ')' || c == '[' || c == ']':
			out = append(out, token{kind: c, text: string(c)})
			i++
		case c == '"':
			j := i + 1
			for ; j < len(src); j++ {
				if src[j] == '\\' {
					j++
					continue
				}
				if src[j] == '"' {
					break
				}
			}
			if j >= len(src) {
				return nil, badRequest("invalidFilter", "unterminated string")
			}
			var s string
			if err := json.Unmarshal([]byte(src[i:j+1]), &s); err != nil {
				return nil, badRequest("invalidFilter", "invalid string %s", src[i:j+1])
			}
			out = append(out, token{kind: 's', text: src[i : j+1], str: s})
			i = j + 1
		default:
			j := i
			for j < len(src) && !strings.ContainsRune(" \t\r\n()[]\"", rune(src[j])) {
				j++
			}
			out = append(out, token{kind: 'w', text: src[i:j]})
			i = j
		}
	}
	return out, nil
}

type parser struct {
	toks  []token
	pos   int
	depth int
}

// ParseFilter parses a filter.
func ParseFilter(src string) (*Filter, error) {
	if len(src) > MaxFilterBytes {
		return nil, badRequest("invalidFilter", "filter longer than %d bytes", MaxFilterBytes)
	}
	toks, err := lex(src)
	if err != nil {
		return nil, err
	}
	p := &parser{toks: toks}
	n, err := p.or(false)
	if err != nil {
		return nil, err
	}
	if p.pos != len(p.toks) {
		return nil, badRequest("invalidFilter", "unexpected %q", p.toks[p.pos].text)
	}
	return &Filter{root: n, src: src}, nil
}

func (p *parser) peek() *token {
	if p.pos < len(p.toks) {
		return &p.toks[p.pos]
	}
	return nil
}

func (p *parser) keyword(kw string) bool {
	t := p.peek()
	if t != nil && t.kind == 'w' && strings.EqualFold(t.text, kw) {
		p.pos++
		return true
	}
	return false
}

func (p *parser) expect(kind byte) error {
	t := p.peek()
	if t == nil || t.kind != kind {
		if t == nil {
			return badRequest("invalidFilter", "expected %q at the end", string(kind))
		}
		return badRequest("invalidFilter", "expected %q, got %q", string(kind), t.text)
	}
	p.pos++
	return nil
}

func (p *parser) enter() error {
	p.depth++
	if p.depth > maxFilterDepth {
		return badRequest("invalidFilter", "filter nested deeper than %d", maxFilterDepth)
	}
	return nil
}

func (p *parser) or(inValue bool) (node, error) {
	l, err := p.and(inValue)
	if err != nil {
		return nil, err
	}
	for p.keyword("or") {
		r, err := p.and(inValue)
		if err != nil {
			return nil, err
		}
		l = &logical{l: l, r: r}
	}
	return l, nil
}

func (p *parser) and(inValue bool) (node, error) {
	l, err := p.not(inValue)
	if err != nil {
		return nil, err
	}
	for p.keyword("and") {
		r, err := p.not(inValue)
		if err != nil {
			return nil, err
		}
		l = &logical{and: true, l: l, r: r}
	}
	return l, nil
}

func (p *parser) not(inValue bool) (node, error) {
	if t := p.peek(); t != nil && t.kind == 'w' && strings.EqualFold(t.text, "not") {
		p.pos++
		if err := p.enter(); err != nil {
			return nil, err
		}
		defer func() { p.depth-- }()
		if err := p.expect('('); err != nil {
			return nil, err
		}
		x, err := p.or(inValue)
		if err != nil {
			return nil, err
		}
		if err := p.expect(')'); err != nil {
			return nil, err
		}
		return &negation{x: x}, nil
	}
	return p.atom(inValue)
}

var compareOps = map[string]bool{"eq": true, "ne": true, "co": true, "sw": true, "ew": true, "gt": true, "lt": true, "ge": true, "le": true}

func (p *parser) atom(inValue bool) (node, error) {
	t := p.peek()
	if t == nil {
		return nil, badRequest("invalidFilter", "unexpected end of filter")
	}
	if t.kind == '(' {
		p.pos++
		if err := p.enter(); err != nil {
			return nil, err
		}
		defer func() { p.depth-- }()
		x, err := p.or(inValue)
		if err != nil {
			return nil, err
		}
		if err := p.expect(')'); err != nil {
			return nil, err
		}
		return x, nil
	}
	if t.kind != 'w' {
		return nil, badRequest("invalidFilter", "expected an attribute, got %q", t.text)
	}
	p.pos++
	path, err := parseAttrPath(t.text)
	if err != nil {
		return nil, err
	}
	if nt := p.peek(); nt != nil && nt.kind == '[' {
		if inValue || path.sub != "" {
			return nil, badRequest("invalidFilter", "a value filter cannot be nested or follow a sub-attribute")
		}
		p.pos++
		if err := p.enter(); err != nil {
			return nil, err
		}
		defer func() { p.depth-- }()
		f, err := p.or(true)
		if err != nil {
			return nil, err
		}
		if err := p.expect(']'); err != nil {
			return nil, err
		}
		return &valueFilter{path: path, filter: f}, nil
	}
	opTok := p.peek()
	if opTok == nil || opTok.kind != 'w' {
		return nil, badRequest("invalidFilter", "expected an operator after %q", t.text)
	}
	op := strings.ToLower(opTok.text)
	p.pos++
	if op == "pr" {
		return &present{path: path}, nil
	}
	if !compareOps[op] {
		return nil, badRequest("invalidFilter", "unknown operator %q", opTok.text)
	}
	vt := p.peek()
	if vt == nil {
		return nil, badRequest("invalidFilter", "expected a value after %q", opTok.text)
	}
	p.pos++
	var value any
	switch {
	case vt.kind == 's':
		value = vt.str
	case vt.kind == 'w' && vt.text == "true":
		value = true
	case vt.kind == 'w' && vt.text == "false":
		value = false
	case vt.kind == 'w' && vt.text == "null":
		value = nil
	case vt.kind == 'w':
		n, err := strconv.ParseFloat(vt.text, 64)
		if err != nil || !json.Valid([]byte(vt.text)) {
			return nil, badRequest("invalidFilter", "invalid value %q", vt.text)
		}
		value = n
	default:
		return nil, badRequest("invalidFilter", "invalid value %q", vt.text)
	}
	switch value.(type) {
	case bool, nil:
		if op != "eq" && op != "ne" {
			return nil, badRequest("invalidFilter", "%s cannot compare %s", op, vt.text)
		}
	case float64:
		if op == "co" || op == "sw" || op == "ew" {
			return nil, badRequest("invalidFilter", "%s cannot compare a number", op)
		}
	}
	return &compare{path: path, op: op, value: value}, nil
}

// parseAttrPath reads [URI ":"] ATTRNAME ["." subAttr].
func parseAttrPath(s string) (attrPath, error) {
	var p attrPath
	rest := s
	if len(s) > 4 && strings.EqualFold(s[:4], "urn:") {
		i := strings.LastIndexByte(s, ':')
		p.urn, rest = s[:i], s[i+1:]
		if strings.EqualFold(p.urn, UserSchema) || strings.EqualFold(p.urn, GroupSchema) {
			p.urn = ""
		}
	}
	attr, sub, hasSub := strings.Cut(rest, ".")
	if !validName(attr) || hasSub && !validName(sub) {
		return p, badRequest("invalidFilter", "invalid attribute path %q", s)
	}
	p.attr, p.sub = strings.ToLower(attr), strings.ToLower(sub)
	p.rawAttr, p.rawSub = attr, sub
	return p, nil
}

// validName: ATTRNAME = ALPHA *(nameChar), nameChar = "-" / "_" / DIGIT /
// ALPHA (RFC 7643 §2.1), and "$ref".
func validName(s string) bool {
	if s == "$ref" {
		return true
	}
	if s == "" || len(s) > 128 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		alpha := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
		if i == 0 && !alpha {
			return false
		}
		if !alpha && !(c >= '0' && c <= '9') && c != '-' && c != '_' {
			return false
		}
	}
	return true
}
