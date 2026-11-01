package scim

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

// seed10k fills a Memory with 10,000 users and 200 groups of 50 members.
func seed10k(tb testing.TB) *Server {
	tb.Helper()
	mem := NewMemory()
	ctx := context.Background()
	for i := 0; i < 10_000; i++ {
		u := User{
			Schemas:  []string{UserSchema},
			ID:       fmt.Sprintf("u-%05d", i),
			UserName: fmt.Sprintf("user%05d@example.org", i),
			Name:     &Name{GivenName: fmt.Sprintf("G%d", i%100), FamilyName: fmt.Sprintf("F%d", i)},
			Emails:   []Email{{Value: fmt.Sprintf("user%05d@example.org", i), Type: "work", Primary: true}},
		}
		if err := mem.CreateUser(ctx, u); err != nil {
			tb.Fatal(err)
		}
	}
	for g := 0; g < 200; g++ {
		grp := Group{Schemas: []string{GroupSchema}, ID: fmt.Sprintf("g-%03d", g), DisplayName: fmt.Sprintf("group%d", g)}
		for k := 0; k < 50; k++ {
			grp.Members = append(grp.Members, Ref{Value: fmt.Sprintf("u-%05d", (g*50+k)%10_000)})
		}
		if err := mem.CreateGroup(ctx, grp); err != nil {
			tb.Fatal(err)
		}
	}
	return &Server{Backend: mem}
}

func benchList(b *testing.B, target string) {
	srv := seed10k(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r := httptest.NewRequest(http.MethodGet, target, nil)
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, r)
		if w.Code != 200 {
			b.Fatalf("%d %s", w.Code, w.Body)
		}
	}
}

// BenchmarkListFilter10k: one equality and one substring filter over 10,000
// users held in the Memory backend.
func BenchmarkListFilterEq10k(b *testing.B) {
	benchList(b, "/Users?filter=userName%20eq%20%22user05000@example.org%22")
}

func BenchmarkListFilterCo10k(b *testing.B) {
	benchList(b, "/Users?filter=name.givenName%20eq%20%22G7%22%20and%20emails%5Btype%20eq%20%22work%22%5D&count=50")
}

func BenchmarkListAll10k(b *testing.B) { benchList(b, "/Users?count=100") }
