package scim

import (
	"context"
	"slices"
	"strings"
	"sync"
)

// Backend stores Users and Groups. The Server assigns ids, timestamps and
// versions, validates input and applies PATCH; the Backend keeps what it is
// given and enforces what only it can see: uniqueness (ErrConflict), that a
// member exists (InvalidValue), and that a replaced resource is still the
// version that was read (ErrPrecondition).
//
// List methods receive the filter, or nil. A Backend may use it to narrow
// the result (Filter.Equality names the cheap cases), or ignore it: the
// Server applies the filter exactly to whatever comes back.
type Backend interface {
	CreateUser(ctx context.Context, u User) error
	// GetUser returns a user with Groups filled in, or ErrNotFound.
	GetUser(ctx context.Context, id string) (User, error)
	// ReplaceUser stores u if the stored user's Meta.Version is ifVersion.
	ReplaceUser(ctx context.Context, u User, ifVersion string) error
	DeleteUser(ctx context.Context, id string) error
	ListUsers(ctx context.Context, f *Filter) ([]User, error)

	CreateGroup(ctx context.Context, g Group) error
	GetGroup(ctx context.Context, id string) (Group, error)
	ReplaceGroup(ctx context.Context, g Group, ifVersion string) error
	DeleteGroup(ctx context.Context, id string) error
	ListGroups(ctx context.Context, f *Filter) ([]Group, error)
}

// ConditionalDeleter is implemented by a Backend that can delete a resource
// only if it is still at the version the client's If-Match named (ErrPrecondition
// otherwise). Without it, DELETE with If-Match checks the version and then
// deletes in two steps, and a write landing between them is deleted unseen.
type ConditionalDeleter interface {
	DeleteUserIf(ctx context.Context, id, ifVersion string) error
	DeleteGroupIf(ctx context.Context, id, ifVersion string) error
}

// Memory is a Backend in memory: tests, and the reference for writing
// another. userName is unique without regard to case (RFC 7643 §4.1.1),
// group display names are not unique, members must exist, and deleting a
// user or group removes it from every group.
type Memory struct {
	mu     sync.RWMutex
	users  map[string]User
	groups map[string]Group
}

// NewMemory returns an empty Memory backend.
func NewMemory() *Memory {
	return &Memory{users: map[string]User{}, groups: map[string]Group{}}
}

func (m *Memory) userNameTaken(name, except string) bool {
	for id, u := range m.users {
		if id != except && strings.EqualFold(u.UserName, name) {
			return true
		}
	}
	return false
}

func (m *Memory) CreateUser(_ context.Context, u User) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.userNameTaken(u.UserName, "") {
		return ErrConflict
	}
	u.Groups = nil
	m.users[u.ID] = u
	return nil
}

// withGroups fills a user's groups (direct memberships).
func (m *Memory) withGroups(u User) User {
	u.Groups = nil
	for _, g := range m.groups {
		for _, mem := range g.Members {
			if mem.Value == u.ID {
				u.Groups = append(u.Groups, Ref{Value: g.ID, Display: g.DisplayName, Type: "direct"})
			}
		}
	}
	slices.SortFunc(u.Groups, func(a, b Ref) int { return strings.Compare(a.Value, b.Value) })
	return u
}

func (m *Memory) GetUser(_ context.Context, id string) (User, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	u, ok := m.users[id]
	if !ok {
		return User{}, ErrNotFound
	}
	return m.withGroups(u), nil
}

func (m *Memory) ReplaceUser(_ context.Context, u User, ifVersion string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cur, ok := m.users[u.ID]
	if !ok {
		return ErrNotFound
	}
	if cur.Meta.Version != ifVersion {
		return ErrPrecondition
	}
	if m.userNameTaken(u.UserName, u.ID) {
		return ErrConflict
	}
	u.Groups = nil
	m.users[u.ID] = u
	return nil
}

func (m *Memory) DeleteUser(ctx context.Context, id string) error {
	return m.DeleteUserIf(ctx, id, "")
}

// DeleteUserIf deletes the user if its version is ifVersion ("" for any).
func (m *Memory) DeleteUserIf(_ context.Context, id, ifVersion string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.users[id]
	if !ok {
		return ErrNotFound
	}
	if ifVersion != "" && u.Meta.Version != ifVersion {
		return ErrPrecondition
	}
	delete(m.users, id)
	m.dropMember(id)
	return nil
}

func (m *Memory) dropMember(id string) {
	for gid, g := range m.groups {
		kept := g.Members[:0:0]
		for _, mem := range g.Members {
			if mem.Value != id {
				kept = append(kept, mem)
			}
		}
		if len(kept) != len(g.Members) {
			g.Members = kept
			m.groups[gid] = g
		}
	}
}

func (m *Memory) ListUsers(_ context.Context, f *Filter) ([]User, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if attr, want, ok := hint(f, "username", "externalid", "id"); ok {
		var out []User
		for _, u := range m.users {
			if attr == "username" && strings.EqualFold(u.UserName, want) ||
				attr == "externalid" && u.ExternalID == want || attr == "id" && u.ID == want {
				out = append(out, m.withGroups(u))
			}
		}
		return out, nil
	}
	// One pass over the memberships, not one per user.
	byUser := map[string][]Ref{}
	for _, g := range m.groups {
		for _, mem := range g.Members {
			byUser[mem.Value] = append(byUser[mem.Value], Ref{Value: g.ID, Display: g.DisplayName, Type: "direct"})
		}
	}
	out := make([]User, 0, len(m.users))
	for _, u := range m.users {
		u.Groups = byUser[u.ID]
		slices.SortFunc(u.Groups, func(a, b Ref) int { return strings.Compare(a.Value, b.Value) })
		out = append(out, u)
	}
	return out, nil
}

// checkMembers resolves each member to a user or group and fills its type.
func (m *Memory) checkMembers(g *Group) error {
	for i, mem := range g.Members {
		switch {
		case m.users[mem.Value].ID != "":
			g.Members[i].Type = "User"
		case m.groups[mem.Value].ID != "" && mem.Value != g.ID:
			g.Members[i].Type = "Group"
		default:
			return InvalidValue("member " + mem.Value + " does not exist")
		}
	}
	return nil
}

func (m *Memory) CreateGroup(_ context.Context, g Group) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	g.Members = slices.Clone(g.Members)
	if err := m.checkMembers(&g); err != nil {
		return err
	}
	m.groups[g.ID] = g
	return nil
}

func (m *Memory) GetGroup(_ context.Context, id string) (Group, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	g, ok := m.groups[id]
	if !ok {
		return Group{}, ErrNotFound
	}
	g.Members = slices.Clone(g.Members)
	return g, nil
}

func (m *Memory) ReplaceGroup(_ context.Context, g Group, ifVersion string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cur, ok := m.groups[g.ID]
	if !ok {
		return ErrNotFound
	}
	if cur.Meta.Version != ifVersion {
		return ErrPrecondition
	}
	g.Members = slices.Clone(g.Members)
	if err := m.checkMembers(&g); err != nil {
		return err
	}
	m.groups[g.ID] = g
	return nil
}

func (m *Memory) DeleteGroup(ctx context.Context, id string) error {
	return m.DeleteGroupIf(ctx, id, "")
}

// DeleteGroupIf deletes the group if its version is ifVersion ("" for any).
func (m *Memory) DeleteGroupIf(_ context.Context, id, ifVersion string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	g, ok := m.groups[id]
	if !ok {
		return ErrNotFound
	}
	if ifVersion != "" && g.Meta.Version != ifVersion {
		return ErrPrecondition
	}
	delete(m.groups, id)
	m.dropMember(id)
	return nil
}

func (m *Memory) ListGroups(_ context.Context, f *Filter) ([]Group, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	attr, want, narrow := hint(f, "displayname", "externalid", "id")
	out := make([]Group, 0, len(m.groups))
	for _, g := range m.groups {
		if narrow && !(attr == "displayname" && strings.EqualFold(g.DisplayName, want) ||
			attr == "externalid" && g.ExternalID == want || attr == "id" && g.ID == want) {
			continue
		}
		g.Members = slices.Clone(g.Members)
		out = append(out, g)
	}
	return out, nil
}

// hint extracts the single top-level equality of a filter, if any, so that a
// list can skip what cannot match. The Server applies the whole filter again,
// so a hint only has to be a superset of the answer. Only the attributes
// named in allowed are narrowed; others return everything.
func hint(f *Filter, allowed ...string) (attr, value string, ok bool) {
	if f == nil {
		return "", "", false
	}
	attr, value, ok = f.Equality()
	if !ok || !slices.Contains(allowed, attr) {
		return "", "", false
	}
	return attr, value, true
}
