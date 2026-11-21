package scim

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

// Security audit 2026-11-21 (secaudit5). RFC 7643 §4.1.1: userName "MUST be
// unique across the service provider's entire set of Users ... and is case
// insensitive". It names no normalisation, so the policy is ours: format
// characters (Cf) and edge white space are refused, and uniqueness is compared
// on NFKC + case fold.

func ru(codes ...rune) string { return string(codes) }

var lookAlikes = []struct{ name, second string }{
	{"case", "ALICE"},
	{"trailing space", "alice "},
	{"leading space", " alice"},
	{"trailing tab", "alice\t"},
	{"no-break space at the edge", ru(0xa0) + "alice"},
	{"zero width space U+200B", "al" + ru(0x200b) + "ice"},
	{"zero width joiner U+200D", "al" + ru(0x200d) + "ice"},
	{"right-to-left override U+202E", "alice" + ru(0x202e)},
	{"fullwidth a U+FF41", ru(0xff41) + "lice"},
	{"fullwidth all", ru(0xff41, 0xff4c, 0xff49, 0xff43, 0xff45)},
	{"soft hyphen U+00AD", "al" + ru(0xad) + "ice"},
	{"byte order mark U+FEFF", ru(0xfeff) + "alice"},
}

func postUser(s *Server, userName string) (int, string) {
	body := `{"schemas":["` + UserSchema + `"],"userName":` + strconv.Quote(userName) + `}`
	w := httptest.NewRecorder()
	s.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/Users", strings.NewReader(body)))
	return w.Code, w.Body.String()
}

func TestSecaudit5UserNamesThatReadAlikeAreOneName(t *testing.T) {
	for _, c := range lookAlikes {
		t.Run(c.name, func(t *testing.T) {
			s := &Server{Backend: NewMemory()}
			if got, _ := postUser(s, "alice"); got != http.StatusCreated {
				t.Fatalf("alice: %d", got)
			}
			if got, _ := postUser(s, c.second); got == http.StatusCreated {
				t.Errorf("userName %q was created (201) beside \"alice\"; want 409 or 400", c.second)
			}
		})
	}
}

// A rename (PUT) goes through the same two gates.
func TestSecaudit5RenameOntoALookAlikeIsRefused(t *testing.T) {
	for _, c := range lookAlikes {
		t.Run(c.name, func(t *testing.T) {
			s := &Server{Backend: NewMemory()}
			postUser(s, "alice")
			code, body := postUser(s, "bob")
			if code != http.StatusCreated {
				t.Fatalf("bob: %d", code)
			}
			var u User
			if err := json.Unmarshal([]byte(body), &u); err != nil {
				t.Fatal(err)
			}
			put := `{"schemas":["` + UserSchema + `"],"userName":` + strconv.Quote(c.second) + `}`
			w := httptest.NewRecorder()
			s.ServeHTTP(w, httptest.NewRequest(http.MethodPut, "/Users/"+u.ID, strings.NewReader(put)))
			if w.Code == http.StatusOK {
				t.Errorf("bob renamed to %q (200) beside \"alice\"", c.second)
			}
		})
	}
}

// What stays legal: the refusal is not a ban on every non-ASCII name.
func TestSecaudit5OrdinaryUserNamesStillWork(t *testing.T) {
	for _, n := range []string{"alice", "bjensen@example.com", "Zo" + ru(0xeb), "Jos" + ru(0xe9) + " Garc" + ru(0xed) + "a", ru(0x7530, 0x4e2d), "a b"} {
		s := &Server{Backend: NewMemory()}
		if got, body := postUser(s, n); got != http.StatusCreated {
			t.Errorf("%q: %d %s", n, got, body)
		}
	}
}

// The same name, composed and decomposed, is one name.
func TestSecaudit5CanonicalEquivalentNamesAreOneName(t *testing.T) {
	s := &Server{Backend: NewMemory()}
	if got, _ := postUser(s, "Zo"+ru(0xeb)); got != http.StatusCreated {
		t.Fatal(got)
	}
	if got, _ := postUser(s, "Zoe"+ru(0x308)); got == http.StatusCreated {
		t.Error("decomposed spelling created beside the composed one")
	}
}
