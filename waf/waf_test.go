package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

var (
	detectOnce, blockOnce     sync.Once
	detectEngine, blockEngine *Engine
)

func engineFor(t *testing.T, mode string) *Engine {
	t.Helper()
	build := func() *Engine {
		e, err := NewEngine(mode, 1, "", 10<<20)
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
	e, err := NewEngine(ModeDetect, 1, dir, 10<<20)
	if err != nil {
		t.Fatal(err)
	}
	if v := e.Inspect(forwardAuth("GET", "/items?id=1%27%20OR%20%271%27%3D%271", "")); v.Event != nil && hasTag(v.Event, "attack-sqli") {
		t.Fatalf("sqli rules should be removed: %+v", v.Event)
	}
}

func TestHandler_CheckAndEventsApi(t *testing.T) {
	cfg := config{Mode: ModeBlock, Paranoia: 1, Token: "secret"}
	store := NewStore(10)
	h := newHandler(engineFor(t, ModeBlock), store, cfg)

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
}

func TestLoadConfig_Validates(t *testing.T) {
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	if _, err := loadConfig(env(map[string]string{"WAF_MODE": "off"})); err == nil {
		t.Fatal("bad mode accepted")
	}
	if _, err := loadConfig(env(map[string]string{"WAF_PARANOIA": "5"})); err == nil {
		t.Fatal("bad paranoia accepted")
	}
	c, err := loadConfig(env(map[string]string{}))
	if err != nil || c.Mode != ModeDetect || c.Listen != "127.0.0.1:8044" || c.Paranoia != 1 {
		t.Fatalf("defaults: %+v %v", c, err)
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
