package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

var (
	detectOnce, blockOnce     sync.Once
	detectEngine, blockEngine *Engine
)

func engineFor(t *testing.T, mode string) *Engine {
	t.Helper()
	build := func() *Engine {
		e, err := NewEngine(mode, 1, "", 10<<20, nil)
		if err != nil {
			t.Fatalf("NewEngine(%s): %v", mode, err)
		}
		return e
	}
	if mode == ModeBlock {
		blockOnce.Do(func() { blockEngine = build() })
		return blockEngine
	}
	detectOnce.Do(func() { detectEngine = build() })
	return detectEngine
}

// forwardAuth builds the subrequest Traefik sends: original headers plus X-Forwarded-*.
func forwardAuth(method, uri, body string) *http.Request {
	r := httptest.NewRequest(method, "http://127.0.0.1:8044/check", strings.NewReader(body))
	r.Header.Set("X-Forwarded-Method", method)
	r.Header.Set("X-Forwarded-Uri", uri)
	r.Header.Set("X-Forwarded-Host", "app.example.com")
	r.Header.Set("X-Forwarded-Proto", "https")
	r.Header.Set("X-Forwarded-For", "203.0.113.7")
	r.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
	r.Header.Set("Accept", "text/html")
	if body != "" {
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	return r
}

func TestCleanRequest_NoEvent(t *testing.T) {
	v := engineFor(t, ModeDetect).Inspect(forwardAuth("GET", "/dashboard?tab=overview", ""))
	if v.Blocked || v.Event != nil {
		t.Fatalf("clean request flagged: blocked=%v event=%+v", v.Blocked, v.Event)
	}
}

func TestSqlInjection_DetectMode_EventNotBlocked(t *testing.T) {
	v := engineFor(t, ModeDetect).Inspect(forwardAuth("GET", "/items?id=1%27%20OR%20%271%27%3D%271", ""))
	if v.Blocked {
		t.Fatal("detect mode must not block")
	}
	if v.Event == nil {
		t.Fatal("expected an event for SQL injection")
	}
	if v.Event.Action != ActionDetected || v.Event.SourceIP != "203.0.113.7" || v.Event.Host != "app.example.com" {
		t.Fatalf("unexpected event: %+v", v.Event)
	}
	if v.Event.AnomalyScore < 5 || !hasTag(v.Event, "attack-sqli") {
		t.Fatalf("expected an sqli rule and a score >= 5: %+v", v.Event)
	}
	for _, r := range v.Event.Rules {
		if r.ID < 910000 || r.Severity == "UNKNOWN" {
			t.Fatalf("setup rule leaked into the event: %+v", r)
		}
	}
}

func TestPathTraversal_BlockMode_Blocks(t *testing.T) {
	v := engineFor(t, ModeBlock).Inspect(forwardAuth("GET", "/files?name=../../../../etc/passwd", ""))
	if !v.Blocked || v.Event == nil || v.Event.Action != ActionBlocked {
		t.Fatalf("expected a blocked event, got blocked=%v event=%+v", v.Blocked, v.Event)
	}
}

func TestCleanPost_NoEvent(t *testing.T) {
	// net/http keeps Content-Length out of r.Header; a missing one trips CRS 920180 on any POST.
	body := "name=" + strings.Repeat("x", 500_000)
	v := engineFor(t, ModeBlock).Inspect(forwardAuth("POST", "/settings", body))
	if v.Blocked || v.Event != nil {
		t.Fatalf("clean POST flagged: blocked=%v event=%+v", v.Blocked, v.Event)
	}
}

func TestBodyIsInspected(t *testing.T) {
	v := engineFor(t, ModeDetect).Inspect(forwardAuth("POST", "/login", "user=admin&pass=1%27%20UNION%20SELECT%20password%20FROM%20users--"))
	if v.Event == nil || !hasTag(v.Event, "attack-sqli") {
		t.Fatalf("expected sqli from the body, got %+v", v.Event)
	}
}

func TestExclusionFile_RemovesRule(t *testing.T) {
	dir := t.TempDir()
	// 942100 is the libinjection SQLi rule; removing the whole SQLi family proves after-crs.conf loads.
	if err := os.WriteFile(filepath.Join(dir, "after-crs.conf"), []byte("SecRuleRemoveByTag attack-sqli\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	e, err := NewEngine(ModeDetect, 1, dir, 10<<20, nil)
	if err != nil {
		t.Fatal(err)
	}
	if v := e.Inspect(forwardAuth("GET", "/items?id=1%27%20OR%20%271%27%3D%271", "")); v.Event != nil && hasTag(v.Event, "attack-sqli") {
		t.Fatalf("sqli rules should be removed: %+v", v.Event)
	}
}

func writePlugin(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(dir, "plugins"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "plugins", name), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

const sqliURI = "/items?id=1%27%20OR%20%271%27%3D%271"

// The before rule only acts on the variable the config file sets, so it passes only in CRS order.
func TestPlugins_ConfigLoadsBeforeBefore(t *testing.T) {
	dir := t.TempDir()
	writePlugin(t, dir, "test-config.conf", `SecAction "id:9001,phase:1,pass,nolog,setvar:tx.test_plugin_enabled=1"`)
	writePlugin(t, dir, "test-before.conf", `SecRule TX:test_plugin_enabled "@eq 1" "id:9002,phase:1,pass,nolog,ctl:ruleRemoveByTag=attack-sqli"`)
	e, err := NewEngine(ModeDetect, 1, dir, 10<<20, nil)
	if err != nil {
		t.Fatal(err)
	}
	if v := e.Inspect(forwardAuth("GET", sqliURI, "")); v.Event != nil && hasTag(v.Event, "attack-sqli") {
		t.Fatalf("plugin exclusion did not apply: %+v", v.Event)
	}
}

// SecRuleRemoveByTag only removes rules already loaded, so this passes only after the CRS.
func TestPlugins_AfterLoadsAfterCrs(t *testing.T) {
	dir := t.TempDir()
	writePlugin(t, dir, "test-after.conf", "SecRuleRemoveByTag attack-sqli\n")
	e, err := NewEngine(ModeDetect, 1, dir, 10<<20, nil)
	if err != nil {
		t.Fatal(err)
	}
	if v := e.Inspect(forwardAuth("GET", sqliURI, "")); v.Event != nil && hasTag(v.Event, "attack-sqli") {
		t.Fatalf("after plugin did not apply: %+v", v.Event)
	}
}

func TestClientAddress_RightMostUntrusted(t *testing.T) {
	cloudflare, err := parseTrusted("173.245.48.0/20,2400:cb00::/32")
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name, xff, want string
		trusted         bool
	}{
		{"direct, no trust", "203.0.113.7", "203.0.113.7", false},
		{"spoofed entry without trust", "198.51.100.1, 203.0.113.7", "203.0.113.7", false},
		{"behind Cloudflare", "203.0.113.7, 173.245.48.10", "203.0.113.7", true},
		{"spoof behind Cloudflare", "198.51.100.1, 203.0.113.7, 173.245.48.10", "203.0.113.7", true},
		{"IPv6 edge", "2001:db8::7, 2400:cb00::1", "2001:db8::7", true},
		{"only trusted hops", "173.245.48.10", "173.245.48.10", true},
		{"malformed left of client", "junk, 203.0.113.7, 173.245.48.10", "203.0.113.7", true},
	}
	for _, c := range cases {
		r := forwardAuth("GET", "/", "")
		r.Header.Set("X-Forwarded-For", c.xff)
		var trusted []netip.Prefix
		if c.trusted {
			trusted = cloudflare
		}
		if got := clientAddress(r, trusted); got != c.want {
			t.Errorf("%s: got %s, want %s", c.name, got, c.want)
		}
	}
}

// forwardAuth sends only the connecting address in X-Forwarded-For, which behind Cloudflare is the edge.
func TestClientAddress_CloudflareEdge_UsesCFConnectingIP(t *testing.T) {
	cloudflare, _ := parseTrusted("172.64.0.0/13,2400:cb00::/32")
	cases := []struct {
		name, xff, cf, want string
		trusted             []netip.Prefix
	}{
		{"edge with header", "172.68.150.126", "203.0.113.7", "203.0.113.7", cloudflare},
		{"edge with IPv6 visitor", "172.68.150.126", "2001:db8::7", "2001:db8::7", cloudflare},
		{"edge without header", "172.68.150.126", "", "172.68.150.126", cloudflare},
		{"edge with junk header", "172.68.150.126", "nope", "172.68.150.126", cloudflare},
		// A direct client is not a trusted peer, so its header is ignored.
		{"direct client spoofing the header", "198.51.100.9", "203.0.113.7", "198.51.100.9", cloudflare},
		{"no trust configured", "172.68.150.126", "203.0.113.7", "172.68.150.126", nil},
	}
	for _, c := range cases {
		r := forwardAuth("GET", "/", "")
		r.Header.Set("X-Forwarded-For", c.xff)
		if c.cf != "" {
			r.Header.Set("CF-Connecting-IP", c.cf)
		}
		if got := clientAddress(r, c.trusted); got != c.want {
			t.Errorf("%s: got %s, want %s", c.name, got, c.want)
		}
	}
}

func TestParseTrusted(t *testing.T) {
	p, err := parseTrusted(" 10.0.0.1 , 2606:4700::/32,,198.51.100.0/24")
	if err != nil || len(p) != 3 || p[0].String() != "10.0.0.1/32" {
		t.Fatalf("parse: %v %v", p, err)
	}
	if _, err := parseTrusted("10.0.0.0/33"); err == nil {
		t.Fatal("bad prefix accepted")
	}
}

func TestHandler_CheckAndEventsApi(t *testing.T) {
	cfg := config{Mode: ModeBlock, Paranoia: 1, Token: "secret"}
	store := NewStore(10)
	h := newHandler(engineFor(t, ModeBlock), store, NewBanList(), cfg)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, forwardAuth("GET", "/ok", ""))
	if rec.Code != http.StatusOK {
		t.Fatalf("clean /check = %d", rec.Code)
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, forwardAuth("GET", "/files?name=../../../../etc/passwd", ""))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("attack /check = %d", rec.Code)
	}

	for _, auth := range []string{"", "Bearer wrong", "secret"} {
		req := httptest.NewRequest("GET", "/api/events", nil)
		if auth != "" {
			req.Header.Set("Authorization", auth)
		}
		rec = httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("auth %q: got %d, want 401", auth, rec.Code)
		}
	}

	req := httptest.NewRequest("GET", "/api/events?since=0", nil)
	req.Header.Set("Authorization", "Bearer secret")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var page EventPage
	if err := json.Unmarshal(rec.Body.Bytes(), &page); err != nil {
		t.Fatal(err)
	}
	if page.Stats.Inspected != 2 || page.Stats.Blocked != 1 || len(page.Events) != 1 || page.Next != 2 {
		t.Fatalf("unexpected page: %+v", page)
	}
}

func TestStore_RingKeepsNewestAndCursorAdvances(t *testing.T) {
	s := NewStore(3)
	for i := 0; i < 5; i++ {
		s.Record(Verdict{Event: &Event{Action: ActionDetected}})
	}
	page := s.Since(0, 100, ModeDetect, 1)
	if len(page.Events) != 3 || page.Events[0].Seq != 3 || page.Next != 6 {
		t.Fatalf("ring: %+v", page)
	}
	if page = s.Since(6, 100, ModeDetect, 1); len(page.Events) != 0 || page.Next != 6 {
		t.Fatalf("caught up: %+v", page)
	}
	if page = s.Since(4, 1, ModeDetect, 1); len(page.Events) != 1 || page.Next != 5 {
		t.Fatalf("limit: %+v", page)
	}
	// A cursor from a previous, longer-lived instance is past the end.
	if page = s.Since(1_000_000, 100, ModeDetect, 1); len(page.Events) != 0 || page.Next != 6 {
		t.Fatalf("past the end: %+v", page)
	}
}

func TestLoadConfig_Validates(t *testing.T) {
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	if _, err := loadConfig(env(map[string]string{"WAF_MODE": "off"})); err == nil {
		t.Fatal("bad mode accepted")
	}
	if _, err := loadConfig(env(map[string]string{"WAF_PARANOIA": "5"})); err == nil {
		t.Fatal("bad paranoia accepted")
	}
	if _, err := loadConfig(env(map[string]string{"WAF_TRUSTED_PROXIES": "not-an-ip"})); err == nil {
		t.Fatal("bad trusted proxy accepted")
	}
	c, err := loadConfig(env(map[string]string{}))
	if err != nil || c.Mode != ModeDetect || c.Listen != "127.0.0.1:8044" || c.Paranoia != 1 {
		t.Fatalf("defaults: %+v %v", c, err)
	}
}

func TestBanList_ExactRangeAndExpiry(t *testing.T) {
	b := NewBanList()
	now := time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)
	b.now = func() time.Time { return now }
	err := b.Replace([]Ban{
		{IP: "203.0.113.7", Expires: now.Add(time.Hour)},
		{IP: "198.51.100.0/24", Expires: now.Add(time.Hour)},
		{IP: "2001:db8::/64", Expires: now.Add(time.Hour)},
		{IP: "192.0.2.1", Expires: now.Add(-time.Minute)}, // already expired: dropped
	})
	if err != nil {
		t.Fatal(err)
	}
	for ip, want := range map[string]bool{
		"203.0.113.7": true, "198.51.100.42": true, "2001:db8::5": true, "::ffff:203.0.113.7": true,
		"203.0.113.8": false, "192.0.2.1": false, "not-an-ip": false,
	} {
		if got := b.Banned(ip); got != want {
			t.Errorf("Banned(%s) = %v, want %v", ip, got, want)
		}
	}
	if page := b.List(); page.Count != 3 {
		t.Fatalf("list: %+v", page)
	}
	now = now.Add(2 * time.Hour) // every entry lapses without another sync
	if b.Banned("203.0.113.7") || b.Banned("198.51.100.42") || b.List().Count != 0 {
		t.Fatal("bans must expire on their own")
	}
}

func TestBanList_RejectsBadEntries(t *testing.T) {
	b := NewBanList()
	future := time.Now().Add(time.Hour)
	if err := b.Replace([]Ban{{IP: "nope", Expires: future}}); err == nil {
		t.Fatal("bad IP accepted")
	}
	if err := b.Replace([]Ban{{IP: "203.0.113.7"}}); err == nil {
		t.Fatal("ban without expiry accepted")
	}
}

func TestHandler_BannedClientRefusedInDetectMode(t *testing.T) {
	cfg := config{Mode: ModeDetect, Paranoia: 1, Token: "secret"}
	store := NewStore(10)
	h := newHandler(engineFor(t, ModeDetect), store, NewBanList(), cfg)

	put := func(auth, body string) int {
		req := httptest.NewRequest("PUT", "/api/bans", strings.NewReader(body))
		if auth != "" {
			req.Header.Set("Authorization", auth)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}
	exp := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	if code := put("", `{"bans":[]}`); code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated PUT = %d", code)
	}
	if code := put("Bearer secret", `{"bans":[{"ip":"203.0.113.7","expires":"`+exp+`"}]}`); code != http.StatusOK {
		t.Fatalf("PUT = %d", code)
	}

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, forwardAuth("GET", "/clean", "")) // forwardAuth sends 203.0.113.7
	if rec.Code != http.StatusForbidden {
		t.Fatalf("banned client in detect mode = %d, want 403", rec.Code)
	}
	if s := store.Since(0, 10, ModeDetect, 1).Stats; s.Banned != 1 || s.Inspected != 0 {
		t.Fatalf("stats: %+v", s)
	}

	// Replacing with an empty list lifts the ban.
	if code := put("Bearer secret", `{"bans":[]}`); code != http.StatusOK {
		t.Fatalf("clearing PUT = %d", code)
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, forwardAuth("GET", "/clean", ""))
	if rec.Code != http.StatusOK {
		t.Fatalf("after clearing = %d", rec.Code)
	}
}

func hasTag(e *Event, tag string) bool {
	for _, r := range e.Rules {
		for _, t := range r.Tags {
			if t == tag {
				return true
			}
		}
	}
	return false
}
