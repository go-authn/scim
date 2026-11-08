package scim

import "strings"

// entityTag is an RFC 7232 §2.3 entity-tag: [ "W/" ] DQUOTE *etagc DQUOTE.
type entityTag struct {
	weak   bool
	opaque string // the opaque-tag, quotes included
}

// etagc = %x21 / %x23-7E / obs-text (RFC 7232 §2.3). A comma and a space-free
// run of other characters may appear inside the quotes, so a list cannot be
// split on commas.
func isETagC(c byte) bool { return c == 0x21 || c >= 0x23 && c != 0x7F }

func skipOWS(s string) string { return strings.TrimLeft(s, " \t") }

// parseETag reads one entity-tag at the start of s.
func parseETag(s string) (t entityTag, rest string, ok bool) {
	if strings.HasPrefix(s, "W/") {
		t.weak, s = true, s[2:]
	}
	if s == "" || s[0] != '"' {
		return t, "", false
	}
	for i := 1; i < len(s); i++ {
		switch {
		case s[i] == '"':
			t.opaque = s[:i+1]
			return t, s[i+1:], true
		case !isETagC(s[i]):
			return t, "", false
		}
	}
	return t, "", false
}

// parseIfNoneMatch parses the field lines of an If-None-Match header,
// If-None-Match = "*" / 1#entity-tag, with the list rule of RFC 7230 §7
// (empty elements are ignored, OWS around commas). Several lines are one list
// (RFC 7230 §3.2.2). Anything that does not parse, and a "*" that is not the
// whole value, yields ok == false: the header is ignored, so the request is
// answered as if it were absent.
func parseIfNoneMatch(lines []string) (tags []entityTag, star, ok bool) {
	elements := 0
	for _, line := range lines {
		s := line
		for {
			s = strings.TrimLeft(s, ", \t")
			if s == "" {
				break
			}
			elements++
			if s[0] == '*' {
				star = true
				s = skipOWS(s[1:])
			} else {
				t, rest, good := parseETag(s)
				if !good {
					return nil, false, false
				}
				tags, s = append(tags, t), skipOWS(rest)
			}
			if s != "" && s[0] != ',' {
				return nil, false, false
			}
		}
	}
	if elements == 0 || star && elements > 1 {
		return nil, false, false
	}
	return tags, star, true
}

// weakMatch is the weak comparison of RFC 7232 §2.3.2: the opaque-tags are
// equal, whether either is marked weak or not.
func weakMatch(a, b entityTag) bool { return a.opaque == b.opaque }

// ifNoneMatchFails reports whether an If-None-Match precondition is false for
// a resource whose current entity-tag is current (RFC 7232 §3.2): "*" is false
// when there is a current representation, a list is false when any of its
// tags matches weakly. A GET answers 304 then. A header that does not parse
// is ignored.
func ifNoneMatchFails(lines []string, current string) bool {
	tags, star, ok := parseIfNoneMatch(lines)
	if !ok {
		return false
	}
	if star {
		return true
	}
	cur, rest, good := parseETag(current)
	if !good || rest != "" {
		return false
	}
	for _, t := range tags {
		if weakMatch(t, cur) {
			return true
		}
	}
	return false
}
