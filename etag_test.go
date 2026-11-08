package scim

import "testing"

func TestParseIfNoneMatch(t *testing.T) {
	// A comma is an etagc: it may sit inside the quotes.
	tags, star, ok := parseIfNoneMatch([]string{`"a,b", W/"c"`})
	if !ok || star || len(tags) != 2 || tags[0].opaque != `"a,b"` || tags[1].opaque != `"c"` || !tags[1].weak {
		t.Fatalf("%v %v %v", tags, star, ok)
	}
	if !ifNoneMatchFails([]string{`"x,y"`}, `W/"x,y"`) || ifNoneMatchFails([]string{`"x"`}, `W/"x,y"`) {
		t.Fatal("comma inside a tag")
	}
	for _, bad := range []string{``, `,`, `"a`, `"a" "b"`, `W/`, `W/a`, `*,*`, `* "a"`, "\"a\x01\"", `"a"x`} {
		if _, _, ok := parseIfNoneMatch([]string{bad}); ok {
			t.Errorf("%q parsed", bad)
		}
	}
	if ifNoneMatchFails(nil, `W/"a"`) {
		t.Fatal("no header")
	}
	if ifNoneMatchFails([]string{`*`}, `W/"a"`) != true {
		t.Fatal("star")
	}
}

// FuzzIfNoneMatch: no input panics, and a header that parses as a list and is
// extended with the current tag (in either spelling) always fails the
// precondition.
func FuzzIfNoneMatch(f *testing.F) {
	for _, s := range []string{``, `*`, `W/"a"`, `"a", W/"b"`, `, ,"a",`, `"a,b"`, `W/"`, `*, "a"`, "\"\x80\""} {
		f.Add(s, `W/"a"`)
	}
	f.Fuzz(func(t *testing.T, header, current string) {
		got := ifNoneMatchFails([]string{header}, current)
		_, star, pok := parseIfNoneMatch([]string{header})
		cur, rest, ok := parseETag(current)
		if !ok || rest != "" {
			if got && !(pok && star) {
				t.Fatalf("%q failed against unparsable current %q", header, current)
			}
			return
		}
		if !pok || star {
			return
		}
		for _, spelling := range []string{cur.opaque, "W/" + cur.opaque} {
			if !ifNoneMatchFails([]string{header + "," + spelling}, current) {
				t.Fatalf("%q + %q did not match %q", header, spelling, current)
			}
		}
	})
}
