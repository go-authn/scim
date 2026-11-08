package scim

import (
	"fmt"
	"math/rand/v2"
	"testing"
	"time"
)

func selectedUsers() []*User {
	t, f := Bool(true), Bool(false)
	ts := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	meta := Meta{ResourceType: "User", Created: ts, LastModified: ts.Add(time.Hour), Location: "https://x/Users/1", Version: `W/"v"`}
	return []*User{
		{},
		{Schemas: []string{UserSchema}, ID: "1", UserName: "Alice", Meta: meta},
		{Schemas: []string{UserSchema}, ID: "2", ExternalID: "ext", UserName: "bob@Example.org", DisplayName: "Bob B",
			Name: &Name{GivenName: "Bob", FamilyName: "Builder", Formatted: "Bob Builder"}, Active: &t,
			Emails: []Email{{Value: "bob@work.org", Type: "work", Primary: true}, {Value: "bob@home.org", Type: "home"}},
			Groups: []Ref{{Value: "g1", Display: "Admins", Type: "direct"}}, Meta: meta},
		{Schemas: []string{UserSchema}, ID: "3", UserName: "carol", Name: &Name{GivenName: "Carol"}, Active: &f,
			Emails: []Email{{Value: "c@x.org"}}, Meta: meta},
	}
}

func selectedGroups() []*Group {
	ts := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	meta := Meta{ResourceType: "Group", Created: ts, LastModified: ts, Version: `W/"g"`}
	return []*Group{
		{},
		{Schemas: []string{GroupSchema}, ID: "g1", DisplayName: "Admins", ExternalID: "e", Members: []Ref{{Value: "1", Type: "User"}, {Value: "2", Type: "User", Display: "Bob"}}, Meta: meta},
		{Schemas: []string{GroupSchema}, ID: "g2", DisplayName: "Empty", Meta: meta},
	}
}

var selectedFilters = []string{
	`userName eq "alice"`, `USERNAME EQ "ALICE"`, `userName co "e"`, `userName sw "b"`, `userName ew "org"`,
	`userName pr`, `externalId pr`, `externalId eq "ext"`, `externalId ne "ext"`, `displayName ne "x"`,
	`name.givenName eq "Bob"`, `NAME.GIVENNAME eq "bob"`, `name.familyName pr`, `name pr`,
	`active eq true`, `active eq false`, `active ne true`, `active pr`,
	`emails pr`, `emails.value co "work"`, `emails[type eq "work"]`, `emails[type eq "work" and primary eq true]`,
	`emails[value ew ".org" and not (type eq "home")]`, `emails.type eq "home"`, `emails eq "bob@home.org"`,
	`groups pr`, `groups.display eq "Admins"`, `groups[value eq "g1"]`,
	`members pr`, `members.value eq "2"`, `members[type eq "User" and display eq "Bob"]`,
	`meta.resourceType eq "User"`, `meta.lastModified gt "2026-01-02T03:04:05Z"`, `meta.version eq "W/\"v\""`,
	`meta[resourceType eq "Group"]`, `id eq "1"`, `id pr`, `schemas pr`, `schemas eq "` + UserSchema + `"`,
	`displayName eq null`, `displayName ne null`, `name.givenName eq null`,
	`not (userName eq "alice")`, `not (emails pr)`, `not (name.givenName eq "Bob" or active eq false)`,
	`userName eq "alice" or (emails pr and active eq true)`,
	`urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:department eq "x"`,
	`urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:department pr`,
	`not (urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:manager.value pr)`,
	`unknownAttr eq "x"`, `unknownAttr pr`, `not (unknownAttr pr)`, `unknownAttr.sub ne "x"`,
}

// TestFilterOnSelectedMap: a filter gives the same answer on the map holding
// only the attributes it names as on the whole object, for every filter and
// resource here.
func TestFilterOnSelectedMap(t *testing.T) {
	for _, src := range selectedFilters {
		f, err := ParseFilter(src)
		if err != nil {
			t.Fatalf("%s: %v", src, err)
		}
		matchedAny := false
		check := func(v any, label string) {
			full, _ := toMap(v)
			sel, _ := toMapSel(v, f.sel)
			if f.Match(full) != f.Match(sel) {
				t.Errorf("%s on %s: whole %v, selected %v (sel %v)", src, label, f.Match(full), f.Match(sel), f.sel)
			}
			matchedAny = matchedAny || f.Match(full)
		}
		for i, u := range selectedUsers() {
			check(u, fmt.Sprintf("user %d", i))
		}
		for i, g := range selectedGroups() {
			check(g, fmt.Sprintf("group %d", i))
		}
		_ = matchedAny
	}
}

// TestFilterOnSelectedMapRandom: random users and filters built from the
// attribute list.
func TestFilterOnSelectedMapRandom(t *testing.T) {
	rng := rand.New(rand.NewPCG(7, 8))
	atoms := []string{`userName eq "u1"`, `userName sw "u"`, `name.givenName co "a"`, `emails[type eq "work"]`, `emails.value ew "x"`,
		`active eq true`, `displayName pr`, `externalId pr`, `groups pr`, `meta.version pr`, `id eq "i2"`, `name.familyName ne "f"`}
	pick := func() string { return atoms[rng.IntN(len(atoms))] }
	for i := 0; i < 3000; i++ {
		src := pick()
		for n := rng.IntN(4); n > 0; n-- {
			switch rng.IntN(3) {
			case 0:
				src = "(" + src + ") and " + pick()
			case 1:
				src = "(" + src + ") or " + pick()
			default:
				src = "not (" + src + ")"
			}
		}
		f, err := ParseFilter(src)
		if err != nil {
			t.Fatalf("%s: %v", src, err)
		}
		u := randomUser(rng)
		full, _ := toMap(u)
		sel, _ := toMapSel(u, f.sel)
		if f.Match(full) != f.Match(sel) {
			t.Fatalf("%s on %+v: whole %v, selected %v", src, u, f.Match(full), f.Match(sel))
		}
	}
}

func randomUser(rng *rand.Rand) *User {
	u := &User{ID: fmt.Sprintf("i%d", rng.IntN(4)), UserName: fmt.Sprintf("u%d", rng.IntN(3))}
	if rng.IntN(2) == 0 {
		u.Name = &Name{GivenName: []string{"a", "b", "ab", ""}[rng.IntN(4)], FamilyName: []string{"f", "g", ""}[rng.IntN(3)]}
	}
	if rng.IntN(2) == 0 {
		a := Bool(rng.IntN(2) == 0)
		u.Active = &a
	}
	if rng.IntN(2) == 0 {
		u.DisplayName = "d"
	}
	if rng.IntN(2) == 0 {
		u.ExternalID = "e"
	}
	for n := rng.IntN(3); n > 0; n-- {
		u.Emails = append(u.Emails, Email{Value: []string{"a@x", "b@y"}[rng.IntN(2)], Type: []string{"work", "home", ""}[rng.IntN(3)], Primary: rng.IntN(2) == 0})
	}
	if rng.IntN(2) == 0 {
		u.Groups = []Ref{{Value: "g"}}
	}
	if rng.IntN(2) == 0 {
		u.Meta.Version = `W/"v"`
	}
	return u
}

// FuzzFilterOnSelectedMap: whatever parses, selected and whole agree.
func FuzzFilterOnSelectedMap(f *testing.F) {
	for _, s := range selectedFilters {
		f.Add(s)
	}
	users, groups := selectedUsers(), selectedGroups()
	f.Fuzz(func(t *testing.T, src string) {
		flt, err := ParseFilter(src)
		if err != nil {
			return
		}
		check := func(v any) {
			full, _ := toMap(v)
			sel, _ := toMapSel(v, flt.sel)
			if flt.Match(full) != flt.Match(sel) {
				t.Fatalf("%q on %+v: whole %v, selected %v", src, v, flt.Match(full), flt.Match(sel))
			}
		}
		for _, u := range users {
			check(u)
		}
		for _, g := range groups {
			check(g)
		}
	})
}
