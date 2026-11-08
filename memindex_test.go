package scim

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"strings"
	"testing"
)

// scanTaken is the old O(N) implementation of userNameTaken, kept as the
// oracle for the index.
func scanTaken(m *Memory, name, except string) bool {
	for id, u := range m.users {
		if id != except && strings.EqualFold(u.UserName, name) {
			return true
		}
	}
	return false
}

// checkIndex fails if names is not exactly the fold of the stored userNames.
func checkIndex(t *testing.T, m *Memory) {
	t.Helper()
	if len(m.names) != len(m.users) {
		t.Fatalf("index has %d entries for %d users", len(m.names), len(m.users))
	}
	for id, u := range m.users {
		if got := m.names[foldKey(u.UserName)]; got != id {
			t.Fatalf("user %q (%q) indexed as %q", id, u.UserName, got)
		}
	}
}

// foldAlphabet: ASCII, the letters whose case orbits have more than two
// members (k/K/Kelvin sign, s/S/long s, the sigmas, the Dz digraphs,
// micro/Mu), dotted and dotless i, a multi-byte letter and invalid bytes.
var foldAlphabet = []string{"a", "A", "k", "K", "K", "s", "S", "ſ", "σ", "ς", "Σ",
	"Ǆ", "ǅ", "ǆ", "µ", "μ", "Μ", "i", "I", "İ", "ı", "é", "É",
	"-", "@", "1", "\xff", "\xfe", "ß", "ẞ"}

func TestFoldKeyMatchesEqualFold(t *testing.T) {
	var all []string
	var gen func(prefix string, n int)
	gen = func(prefix string, n int) {
		all = append(all, prefix)
		if n == 0 {
			return
		}
		for _, a := range foldAlphabet {
			gen(prefix+a, n-1)
		}
	}
	gen("", 2)
	for _, a := range all {
		for _, b := range all {
			if (foldKey(a) == foldKey(b)) != strings.EqualFold(a, b) {
				t.Fatalf("%q vs %q: foldKey equal %v, EqualFold %v", a, b, foldKey(a) == foldKey(b), strings.EqualFold(a, b))
			}
		}
	}
}

func FuzzFoldKey(f *testing.F) {
	f.Add("User", "uSER")
	f.Add("K", "K")
	f.Add("\xff", "\xfe")
	f.Add("ς", "Σ")
	f.Fuzz(func(t *testing.T, a, b string) {
		if (foldKey(a) == foldKey(b)) != strings.EqualFold(a, b) {
			t.Fatalf("%q vs %q", a, b)
		}
	})
}

// TestMemoryIndexAgainstScan drives random creates, replaces and deletes and
// asks, before each write, whether the index and the old scan agree on every
// candidate name; after each write the index must be exactly the stored
// names.
func TestMemoryIndexAgainstScan(t *testing.T) {
	ctx := context.Background()
	rng := rand.New(rand.NewPCG(1, 2))
	m := NewMemory()
	name := func() string {
		var b strings.Builder
		for i := rng.IntN(3) + 1; i > 0; i-- {
			b.WriteString(foldAlphabet[rng.IntN(len(foldAlphabet))])
		}
		return b.String()
	}
	ids := func() string { return fmt.Sprintf("u%d", rng.IntN(12)) }
	for step := 0; step < 20000; step++ {
		id, n := ids(), name()
		for _, probe := range []string{n, strings.ToUpper(n), strings.ToLower(n)} {
			for _, except := range []string{"", id} {
				if m.userNameTaken(probe, except) != scanTaken(m, probe, except) {
					t.Fatalf("step %d: %q except %q: index %v, scan %v", step, probe, except, m.userNameTaken(probe, except), scanTaken(m, probe, except))
				}
			}
		}
		_, exists := m.users[id]
		wantConflict := func(except string) bool { return scanTaken(m, n, except) }
		switch op := rng.IntN(4); {
		case op == 0: // create, also over an existing id (the old name is released)
			want := wantConflict("")
			err := m.CreateUser(ctx, User{ID: id, UserName: n})
			if want != errors.Is(err, ErrConflict) || err != nil && !want {
				t.Fatalf("step %d create %q: %v, scan says conflict=%v", step, n, err, want)
			}
		case op == 1 && exists: // replace
			want := wantConflict(id)
			err := m.ReplaceUser(ctx, User{ID: id, UserName: n}, "")
			if want != errors.Is(err, ErrConflict) || err != nil && !want {
				t.Fatalf("step %d replace %q: %v, scan says conflict=%v", step, n, err, want)
			}
		case op == 2 && exists: // delete
			if err := m.DeleteUser(ctx, id); err != nil {
				t.Fatal(err)
			}
		case op == 3 && exists: // stale replace changes nothing
			if err := m.ReplaceUser(ctx, User{ID: id, UserName: n}, `W/"stale"`); !errors.Is(err, ErrPrecondition) {
				t.Fatalf("stale replace: %v", err)
			}
		}
		checkIndex(t, m)
	}
	if len(m.users) == 0 {
		t.Fatal("the run never held a user")
	}
}

// Through the HTTP layer: PATCH renames, PUT back, conflicts, DELETE frees a name.
func TestMemoryIndexThroughServer(t *testing.T) {
	c, mem := newClient(t)
	const sch = `"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"]`
	_, a, _ := c.do("POST", "/Users", `{`+sch+`,"userName":"Alice"}`)
	_, b, _ := c.do("POST", "/Users", `{`+sch+`,"userName":"bob"}`)
	c.want(409, "POST", "/Users", `{`+sch+`,"userName":"ALICE"}`)
	aid, bid := a["id"].(string), b["id"].(string)
	patch := func(id, name string) int {
		got, _, _ := c.do("PATCH", "/Users/"+id, `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"userName","value":"`+name+`"}]}`)
		return got
	}
	if got := patch(bid, "aLiCe"); got != 409 {
		t.Fatalf("patch onto a taken name: %d", got)
	}
	if got := patch(aid, "carol"); got != 200 {
		t.Fatalf("patch rename: %d", got)
	}
	if got := patch(bid, "ALICE"); got != 200 {
		t.Fatalf("the old name is free after a rename: %d", got)
	}
	c.want(409, "POST", "/Users", `{`+sch+`,"userName":"Carol"}`)
	c.want(204, "DELETE", "/Users/"+aid, "")
	c.want(201, "POST", "/Users", `{`+sch+`,"userName":"CAROL"}`)
	checkIndex(t, mem)
}
