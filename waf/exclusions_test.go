package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Grafana request bodies, each of which trips CRS at paranoia 1 outside the built-in set.
var grafanaBodies = map[string]string{
	"flux vars": `{"queries":[{"refId":"A","query":"from(bucket: \"${bucket}\") |> range(start: ${__from:date:iso}, stop: ${__to:date:iso}) |> filter(fn: (r) => r.host =~ /^${host:regex}$/)"}]}`,
	"influxql":  `{"queries":[{"refId":"A","query":"SELECT mean(\"usage_idle\") FROM \"cpu\" WHERE (\"host\" = 'nas') AND $timeFilter GROUP BY time($__interval) fill(null)","rawQuery":true}]}`,
	"mysql":     `{"queries":[{"refId":"A","rawSql":"SELECT $__timeGroupAlias(created_at, '5m'), count(*) AS value FROM orders WHERE $__timeFilter(created_at) AND status = 'paid' GROUP BY 1 ORDER BY 1"}]}`,
	"logql":     `{"queries":[{"refId":"A","expr":"sum by (level) (count_over_time({job=\"varlogs\"} |= \"error\" | json | line_format \"{{.msg}}\" [5m]))"}]}`,
}

func jsonPost(uri, body string) *http.Request {
	r := forwardAuth("POST", uri, body)
	r.Header.Set("Content-Type", "application/json")
	return r
}

// grafanaRoute is a request through a router whose forwardAuth address is /check?app=grafana.
func grafanaRoute(uri, body string) *http.Request {
	r := jsonPost(uri, body)
	r.URL.RawQuery = "app=grafana"
	return r
}

func TestGrafanaApp_QueryEndpointsPassOnItsRouter(t *testing.T) {
	e := engineFor(t, ModeDetect)
	for name, body := range grafanaBodies {
		for _, uri := range []string{"/api/ds/query?ds_type=influxdb", "/grafana/api/ds/query", "/api/dashboards/db"} {
			if v := e.Inspect(grafanaRoute(uri, body)); v.Event != nil {
				t.Errorf("%s on %s flagged: %+v", name, uri, v.Event.Rules)
			}
		}
		// The same body on another path of the Grafana router is still inspected.
		if v := e.Inspect(grafanaRoute("/api/items", body)); v.Event == nil {
			t.Errorf("%s on /api/items not flagged: the set reached past Grafana's query paths", name)
		}
	}
}

func TestGrafanaApp_OnlyWhereTheRouterOptsIn(t *testing.T) {
	e := engineFor(t, ModeDetect)
	body := grafanaBodies["flux vars"]

	if v := e.Inspect(jsonPost("/api/ds/query", body)); v.Event == nil {
		t.Error("a router without app=grafana must inspect Grafana-shaped paths in full")
	}
	forged := jsonPost("/api/ds/query", body)
	forged.Header.Set("X-Netopt-App", "grafana")
	if v := e.Inspect(forged); v.Event == nil {
		t.Error("a client-sent X-Netopt-App must not opt a request in")
	}
	if v := e.Inspect(grafanaRoute("/index.php/api/ds/query", body)); v.Event == nil {
		t.Error("a PATH_INFO path must not match the Grafana endpoints")
	}
	unknown := jsonPost("/api/ds/query", body)
	unknown.URL.RawQuery = "app=nope"
	if v := e.Inspect(unknown); v.Event == nil {
		t.Error("an unknown app must change nothing")
	}
}

func TestExclusion_ScopedToHostMethodAndPath(t *testing.T) {
	e, err := NewEngine(ModeDetect, 1, "", 10<<20, nil)
	if err != nil {
		t.Fatal(err)
	}
	body := grafanaBodies["influxql"] // trips 942100 only
	list, err := validateExclusions([]Exclusion{{ID: "a", RuleID: 942100, Host: "App.Example.com", Method: "post", Path: "/metrics/"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := e.SetExclusions(list); err != nil {
		t.Fatal(err)
	}
	if v := e.Inspect(jsonPost("/metrics/query?x=1", body)); v.Event != nil {
		t.Fatalf("excluded request flagged: %+v", v.Event.Rules)
	}
	other := jsonPost("/metrics/query", body)
	other.Header.Set("X-Forwarded-Host", "other.example.com")
	if v := e.Inspect(other); v.Event == nil {
		t.Fatal("another host should still be inspected")
	}
	if v := e.Inspect(jsonPost("/reports/query", body)); v.Event == nil {
		t.Fatal("another path should still be inspected")
	}
	put := jsonPost("/metrics/query", body)
	put.Header.Set("X-Forwarded-Method", "PUT")
	if v := e.Inspect(put); v.Event == nil {
		t.Fatal("another method should still be inspected")
	}
	withPort := jsonPost("/metrics/query", body)
	withPort.Header.Set("X-Forwarded-Host", "app.example.com:8443")
	if v := e.Inspect(withPort); v.Event != nil {
		t.Fatal("a host with a port should match its exclusion")
	}
}

func TestExclusion_Validation(t *testing.T) {
	bad := []Exclusion{
		{RuleID: 942100},                              // no scope
		{RuleID: 12, Host: "app.example.com"},         // not a CRS rule
		{RuleID: 942100, Host: `app" ,ctl:x`},         // not a host name
		{RuleID: 942100, Path: `/a" "ctl:ruleEngine`}, // quote in path
		{RuleID: 942100, Path: "no-slash"},
		{RuleID: 942100, Path: "/a", Method: "TRACE"},
	}
	for _, x := range bad {
		if _, err := validateExclusions([]Exclusion{x}); err == nil {
			t.Errorf("accepted %+v", x)
		}
	}
}

func TestRenderExclusions(t *testing.T) {
	got := renderExclusions([]Exclusion{
		{RuleID: 932130, Host: "monitor.example.com", Method: "POST", Path: "/api/ds/query"},
		{RuleID: 920440, Path: "/files/"},
	})
	want := `SecRule REQUEST_HEADERS:Host "@rx ^monitor\.example\.com(?::\d+)?$" "id:2000,phase:1,pass,nolog,t:lowercase,chain"
SecRule REQUEST_METHOD "@streq POST" "chain"
SecRule REQUEST_FILENAME "@beginsWith /api/ds/query" "ctl:ruleRemoveById=932130"
SecRule REQUEST_FILENAME "@beginsWith /files/" "id:2001,phase:1,pass,nolog,ctl:ruleRemoveById=920440"
`
	if got != want {
		t.Fatalf("got:\n%s\nwant:\n%s", got, want)
	}
}

func TestHandler_ExclusionsPersistAndRefuseBadSets(t *testing.T) {
	dir := t.TempDir()
	store, err := NewExclusionStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	engine, err := NewEngine(ModeDetect, 1, "", 10<<20, nil)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config{Token: "secret"}
	h := newHandler(engine, NewStore(10), NewBanList(), mustAllow(t, ""), testModes(t, "", ModeDetect), store, cfg)

	put := func(body string) int {
		r := httptest.NewRequest("PUT", "/api/exclusions", strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer secret")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code
	}
	if code := put(`{"exclusions":[{"id":"x1","ruleId":942100,"host":"app.example.com","path":"/metrics/"}]}`); code != 200 {
		t.Fatalf("PUT = %d", code)
	}
	if code := put(`{"exclusions":[{"id":"x2","ruleId":942100}]}`); code != 400 {
		t.Fatalf("unscoped PUT = %d, want 400", code)
	}

	r := httptest.NewRequest("GET", "/api/exclusions", nil)
	r.Header.Set("Authorization", "Bearer secret")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	var got struct {
		Apps       []string    `json:"apps"`
		Exclusions []Exclusion `json:"exclusions"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Exclusions) != 1 || got.Exclusions[0].ID != "x1" || got.Apps == nil {
		t.Fatalf("a refused PUT changed the set or apps is null: %+v", got)
	}

	reloaded, err := NewExclusionStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if l := reloaded.List(); len(l) != 1 || l[0].Host != "app.example.com" {
		t.Fatalf("not persisted: %+v", l)
	}
}
