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

func (m *Memory) DeleteUser(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.users[id]; !ok {
		return ErrNotFound
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

func (m *Memory) ListUsers(_ context.Context, _ *Filter) ([]User, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]User, 0, len(m.users))
	for _, u := range m.users {
		out = append(out, m.withGroups(u))
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

func (m *Memory) DeleteGroup(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.groups[id]; !ok {
		return ErrNotFound
	}
	delete(m.groups, id)
	m.dropMember(id)
	return nil
}

func (m *Memory) ListGroups(_ context.Context, _ *Filter) ([]Group, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]Group, 0, len(m.groups))
	for _, g := range m.groups {
		g.Members = slices.Clone(g.Members)
		out = append(out, g)
	}
	return out, nil
}
