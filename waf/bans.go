package main

import (
	"fmt"
	"net/netip"
	"sort"
	"sync"
	"time"
)

// maxBans bounds a PUT so a bad caller cannot exhaust memory.
const maxBans = 100000

// Ban is one blocked address or range, set by Network Optimizer.
type Ban struct {
	IP      string    `json:"ip"`
	Expires time.Time `json:"expires"`
}

// BanPage is the bans API response.
type BanPage struct {
	Count int   `json:"count"`
	Bans  []Ban `json:"bans"`
}

type banEntry struct {
	prefix  netip.Prefix
	expires time.Time
}

// BanList answers 403 for banned clients before the rules run. It is replaced whole on every
// sync and kept in memory only: Network Optimizer re-sends it every minute, and every entry
// expires on its own, so bans lapse rather than linger if Network Optimizer stops syncing.
type BanList struct {
	mu      sync.RWMutex
	exact   map[netip.Addr]time.Time
	ranges  []banEntry
	entries []Ban
	now     func() time.Time
}

// NewBanList creates an empty ban list.
func NewBanList() *BanList {
	return &BanList{exact: map[netip.Addr]time.Time{}, now: time.Now}
}

// Replace swaps in a new set of bans. Entries already expired are dropped.
func (b *BanList) Replace(bans []Ban) error {
	if len(bans) > maxBans {
		return fmt.Errorf("at most %d bans, got %d", maxBans, len(bans))
	}
	now := b.now()
	exact := make(map[netip.Addr]time.Time, len(bans))
	var ranges []banEntry
	kept := make([]Ban, 0, len(bans))
	for _, ban := range bans {
		if ban.Expires.IsZero() {
			return fmt.Errorf("ban %q: expires is required", ban.IP)
		}
		if !ban.Expires.After(now) {
			continue
		}
		prefix, err := parseTrusted(ban.IP)
		if err != nil || len(prefix) != 1 {
			return fmt.Errorf("ban %q: not an IP or CIDR", ban.IP)
		}
		p := prefix[0]
		if p.IsSingleIP() {
			exact[p.Addr()] = ban.Expires
		} else {
			ranges = append(ranges, banEntry{prefix: p, expires: ban.Expires})
		}
		kept = append(kept, Ban{IP: p.String(), Expires: ban.Expires.UTC()})
	}
	sort.Slice(kept, func(i, j int) bool { return kept[i].IP < kept[j].IP })

	b.mu.Lock()
	b.exact, b.ranges, b.entries = exact, ranges, kept
	b.mu.Unlock()
	return nil
}

// Banned reports whether ip is covered by an unexpired ban.
func (b *BanList) Banned(ip string) bool {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	addr = addr.Unmap()
	now := b.now()
	b.mu.RLock()
	defer b.mu.RUnlock()
	if exp, ok := b.exact[addr]; ok && exp.After(now) {
		return true
	}
	for _, r := range b.ranges {
		if r.expires.After(now) && r.prefix.Contains(addr) {
			return true
		}
	}
	return false
}

// List returns the unexpired bans.
func (b *BanList) List() BanPage {
	now := b.now()
	b.mu.RLock()
	defer b.mu.RUnlock()
	out := make([]Ban, 0, len(b.entries))
	for _, e := range b.entries {
		if e.Expires.After(now) {
			out = append(out, e)
		}
	}
	return BanPage{Count: len(out), Bans: out}
}
