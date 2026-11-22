package scim

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

// Suspicion 13: POST /.search takes `attributes` as a JSON array, and every
// item of the page re-split and re-parsed the whole list, so a body of 1 MiB
// naming one attribute 100,000 times cost the server a page's worth of that
// work per request. An attribute list has no use past the handful of
// attributes a resource has: more than maxProjectionPaths is refused (400),
// whichever way it arrives.

func projectionServer(t *testing.T) *Server {
	t.Helper()
	s := &Server{Backend: NewMemory()}
	for i := range 3 {
		if code, body := postUser(s, "user"+strconv.Itoa(i)); code != http.StatusCreated {
			t.Fatalf("user %d: %d %s", i, code, body)
		}
	}
	return s
}

func repeatQuoted(name string, n int) string {
	return `"` + strings.Repeat(name+`","`, n-1) + name + `"`
}

func TestAnAttributeListIsBoundedOnOneResource(t *testing.T) {
	s := &Server{Backend: NewMemory()}
	_, body := postUser(s, "alice")
	var u User
	if err := json.Unmarshal([]byte(body), &u); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"attributes", "excludedAttributes"} {
		for _, n := range []int{maxProjectionPaths, maxProjectionPaths + 1} {
			list := strings.TrimSuffix(strings.Repeat("userName,", n), ",")
			w := httptest.NewRecorder()
			s.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/Users/"+u.ID+"?"+field+"="+list, nil))
			want := http.StatusOK
			if n > maxProjectionPaths {
				want = http.StatusBadRequest
			}
			if w.Code != want {
				t.Errorf("GET /Users/{id} %s x %d: %d, want %d", field, n, w.Code, want)
			}
		}
	}
}

func TestAnAttributeListIsBounded(t *testing.T) {
	s := projectionServer(t)
	for _, field := range []string{"attributes", "excludedAttributes"} {
		for _, n := range []int{maxProjectionPaths, maxProjectionPaths + 1, 50_000} {
			body := `{"schemas":["urn:ietf:params:scim:api:messages:2.0:SearchRequest"],"` + field + `":[` + repeatQuoted("userName", n) + `]}`
			w := httptest.NewRecorder()
			s.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/Users/.search", strings.NewReader(body)))
			want := http.StatusOK
			if n > maxProjectionPaths {
				want = http.StatusBadRequest
			}
			if w.Code != want {
				t.Errorf("POST .search %s x %d: %d, want %d", field, n, w.Code, want)
			}

			list := strings.TrimSuffix(strings.Repeat("userName,", n), ",")
			w = httptest.NewRecorder()
			s.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/Users?"+field+"="+list, nil))
			if w.Code != want {
				t.Errorf("GET /Users %s x %d: %d, want %d", field, n, w.Code, want)
			}
		}
	}
}
