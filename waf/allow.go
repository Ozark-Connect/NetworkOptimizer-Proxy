package main

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
)

// maxAllowEntries bounds a PUT so a bad caller cannot exhaust memory.
const maxAllowEntries = 100000

var allowNamePattern = regexp.MustCompile(`^[a-z0-9-]{1,32}$`)

// AllowList is one named list of addresses and ranges.
type AllowList struct {
	Name    string   `json:"name"`
	Entries []string `json:"entries"`
}

// AllowLists holds the named lists Network Optimizer pushes (its Trusted Sources is "trusted").
// A route opts in through its forwardAuth address, /check?allow=<name>. Until a list has been
// pushed at least once, a route that names it is open; after that, only private sources and the
// list's members pass. Lists are saved to dir when set, so a restart never reopens a route.
type AllowLists struct {
	mu    sync.RWMutex
	lists map[string]*Prefixes
	dir   string
}

// NewAllowLists loads any saved lists from dir; an empty dir keeps them in memory only.
func NewAllowLists(dir string) (*AllowLists, error) {
	a := &AllowLists{lists: map[string]*Prefixes{}, dir: dir}
	if dir == "" {
		return a, nil
	}
	data, err := os.ReadFile(a.path())
	if os.IsNotExist(err) {
		return a, nil
	}
	if err != nil {
		return nil, err
	}
	var saved []AllowList
	if err := json.Unmarshal(data, &saved); err != nil {
		return nil, fmt.Errorf("%s: %w", a.path(), err)
	}
	for _, l := range saved {
		p, err := NewPrefixes(l.Entries)
		if err != nil {
			return nil, fmt.Errorf("%s: list %q: %w", a.path(), l.Name, err)
		}
		a.lists[l.Name] = p
	}
	return a, nil
}

func (a *AllowLists) path() string { return filepath.Join(a.dir, "allowlists.json") }

// Replace sets a list's members and saves every list.
func (a *AllowLists) Replace(name string, entries []string) error {
	if !allowNamePattern.MatchString(name) {
		return fmt.Errorf("list name must be 1-32 of a-z, 0-9, and -")
	}
	if len(entries) > maxAllowEntries {
		return fmt.Errorf("at most %d entries, got %d", maxAllowEntries, len(entries))
	}
	p, err := NewPrefixes(entries)
	if err != nil {
		return err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.lists[name] = p
	return a.save()
}

// save writes every list to dir atomically. The caller holds the lock.
func (a *AllowLists) save() error {
	if a.dir == "" {
		return nil
	}
	data, err := json.Marshal(a.snapshot())
	if err != nil {
		return err
	}
	tmp := a.path() + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, a.path())
}

func (a *AllowLists) snapshot() []AllowList {
	out := make([]AllowList, 0, len(a.lists))
	for name, p := range a.lists {
		out = append(out, AllowList{Name: name, Entries: p.Strings()})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// List returns every list.
func (a *AllowLists) List() []AllowList {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.snapshot()
}

// Allowed reports whether ip may use a route that names the list. A list never pushed allows all.
func (a *AllowLists) Allowed(name, ip string) bool {
	a.mu.RLock()
	p, ok := a.lists[name]
	a.mu.RUnlock()
	if !ok {
		return true
	}
	addr, err := parseAddr(ip)
	if err != nil {
		return false
	}
	return isLocal(addr) || p.Contains(addr)
}

// Prefixes is a set of addresses and ranges.
type Prefixes struct {
	prefixes []netip.Prefix
}

// NewPrefixes parses IPs and CIDR ranges; an IP is a single-address range.
func NewPrefixes(entries []string) (*Prefixes, error) {
	p, err := parseTrusted(strings.Join(entries, ","))
	if err != nil {
		return nil, err
	}
	return &Prefixes{prefixes: p}, nil
}

// Contains reports whether addr is in any range.
func (p *Prefixes) Contains(addr netip.Addr) bool { return isTrusted(addr.Unmap(), p.prefixes) }

// Strings returns the ranges, single addresses without a length.
func (p *Prefixes) Strings() []string {
	out := make([]string, 0, len(p.prefixes))
	for _, x := range p.prefixes {
		if x.IsSingleIP() {
			out = append(out, x.Addr().String())
		} else {
			out = append(out, x.String())
		}
	}
	return out
}

func parseAddr(ip string) (netip.Addr, error) {
	addr, err := netip.ParseAddr(strings.TrimSpace(ip))
	return addr.Unmap(), err
}

// isLocal covers RFC 1918, ULA, loopback, and link-local: the LAN side, never from the internet.
// CGNAT (100.64.0.0/10, where Tailscale lives) is not local; add those addresses to the list.
func isLocal(addr netip.Addr) bool {
	return addr.IsPrivate() || addr.IsLoopback() || addr.IsLinkLocalUnicast()
}
