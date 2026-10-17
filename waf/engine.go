package main

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"

	coreruleset "github.com/corazawaf/coraza-coreruleset/v4"
	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"
)

// CRS rule that fires when the inbound anomaly score crosses the blocking threshold.
const inboundAnomalyRuleID = 949110

// appHeader carries a router's app opt-in to the built-in app rules; never taken from the client.
const appHeader = "X-Netopt-App"

var totalScorePattern = regexp.MustCompile(`Total Score: (\d+)`)

// Engine evaluates requests forwarded by Traefik's forwardAuth against Coraza + OWASP CRS. The
// mode can change at runtime (SetMode): Coraza fixes SecRuleEngine at build time, so a change
// builds a new WAF and swaps it in; requests already running finish on the old one.
type Engine struct {
	mu        sync.RWMutex
	waf       coraza.WAF
	mode      string
	trusted   []netip.Prefix
	paranoia  int
	rulesDir  string
	bodyLimit int

	buildMu sync.Mutex // one rebuild at a time, so a mode switch and an exclusion change never cross
	apps    []string
	managed []Exclusion
	methods string
}

// DefaultAllowedMethods adds the REST verbs to CRS's GET HEAD POST OPTIONS. Without them rule
// 911100 scores every PUT, PATCH, and DELETE as critical, which alone blocks it in block mode.
const DefaultAllowedMethods = "GET HEAD POST OPTIONS PUT PATCH DELETE"

// EngineOption adjusts what NewEngine loads beyond the CRS and rulesDir.
type EngineOption func(*Engine)

// WithExclusions loads managed exclusions, already validated.
func WithExclusions(list []Exclusion) EngineOption { return func(e *Engine) { e.managed = list } }

// WithAllowedMethods replaces DefaultAllowedMethods; methods is space-separated and already validated.
func WithAllowedMethods(methods string) EngineOption { return func(e *Engine) { e.methods = methods } }

// NewEngine builds a WAF from the embedded CRS plus optional files in rulesDir: CRS plugins in
// plugins/, before-crs.conf (runtime ctl exclusions), and after-crs.conf (SecRuleRemoveById and
// friends). trusted lists the proxies whose X-Forwarded-For entries are skipped to find the client.
// Every built-in app exclusion set loads; each applies only on routers that name it (/check?app=).
func NewEngine(mode string, paranoia int, rulesDir string, bodyLimit int, trusted []netip.Prefix, opts ...EngineOption) (*Engine, error) {
	e := &Engine{trusted: trusted, paranoia: paranoia, rulesDir: rulesDir, bodyLimit: bodyLimit, apps: AppNames(),
		methods: DefaultAllowedMethods}
	for _, o := range opts {
		o(e)
	}
	if err := e.SetMode(mode); err != nil {
		return nil, err
	}
	return e, nil
}

// Mode is the current mode, detect or block.
func (e *Engine) Mode() string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.mode
}

// SetMode rebuilds the WAF for mode and swaps it in.
func (e *Engine) SetMode(mode string) error {
	if mode != ModeDetect && mode != ModeBlock {
		return fmt.Errorf("mode must be %q or %q, got %q", ModeDetect, ModeBlock, mode)
	}
	e.buildMu.Lock()
	defer e.buildMu.Unlock()
	waf, err := buildWAF(mode, e.paranoia, e.methods, e.rulesDir, e.bodyLimit, e.ruleText(e.managed))
	if err != nil {
		return err
	}
	e.mu.Lock()
	e.waf, e.mode = waf, mode
	e.mu.Unlock()
	return nil
}

// SetExclusions rebuilds the WAF with these managed exclusions in the current mode. A list that
// fails to build is refused and the running WAF is left as it was.
func (e *Engine) SetExclusions(list []Exclusion) error {
	e.buildMu.Lock()
	defer e.buildMu.Unlock()
	mode := e.Mode()
	waf, err := buildWAF(mode, e.paranoia, e.methods, e.rulesDir, e.bodyLimit, e.ruleText(list))
	if err != nil {
		return err
	}
	e.mu.Lock()
	e.waf, e.managed = waf, list
	e.mu.Unlock()
	return nil
}

// Apps lists the built-in app exclusion sets a router can opt into.
func (e *Engine) Apps() []string { return append([]string{}, e.apps...) }

// ruleText is the built-in base and app sets, then the managed exclusions, loaded ahead of
// before-crs.conf.
func (e *Engine) ruleText(managed []Exclusion) string {
	return baseRules + "\n" + appDirectives(e.apps) + renderExclusions(managed)
}

func buildWAF(mode string, paranoia int, methods, rulesDir string, bodyLimit int, builtIn string) (coraza.WAF, error) {
	engineMode := "DetectionOnly"
	if mode == ModeBlock {
		engineMode = "On"
	}

	var parts [5]string
	var err error
	// CRS plugin order: config, before, the CRS rules, after.
	for i, load := range []func() (string, error){
		func() (string, error) { return readGlob(rulesDir, "plugins/*-config.conf") },
		func() (string, error) { return readGlob(rulesDir, "plugins/*-before.conf") },
		func() (string, error) { return readOptional(rulesDir, "before-crs.conf") },
		func() (string, error) { return readGlob(rulesDir, "plugins/*-after.conf") },
		func() (string, error) { return readOptional(rulesDir, "after-crs.conf") },
	} {
		if parts[i], err = load(); err != nil {
			return nil, err
		}
	}

	directives := strings.Join([]string{
		"Include @coraza.conf-recommended",
		"SecRuleEngine " + engineMode,
		"SecRequestBodyAccess On",
		fmt.Sprintf("SecRequestBodyLimit %d", bodyLimit),
		"SecRequestBodyLimitAction ProcessPartial",
		"SecResponseBodyAccess Off",
		"SecAuditEngine Off",
		"Include @crs-setup.conf.example",
		fmt.Sprintf(`SecAction "id:900000,phase:1,pass,t:none,nolog,setvar:tx.blocking_paranoia_level=%d"`, paranoia),
		// 900200 is the CRS setup slot for allowed methods; set before the rules, CRS keeps it.
		fmt.Sprintf(`SecAction "id:900200,phase:1,pass,t:none,nolog,setvar:'tx.allowed_methods=%s'"`, methods),
		parts[0],
		parts[1],
		builtIn,
		parts[2],
		"Include @owasp_crs/*.conf",
		parts[3],
		parts[4],
	}, "\n")

	waf, err := coraza.NewWAF(coraza.NewWAFConfig().
		WithRootFS(coreruleset.FS).
		WithDirectives(directives))
	if err != nil {
		return nil, fmt.Errorf("load rules: %w", err)
	}
	return waf, nil
}

func readOptional(dir, name string) (string, error) {
	if dir == "" {
		return "", nil
	}
	b, err := os.ReadFile(filepath.Join(dir, name))
	if os.IsNotExist(err) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("read %s: %w", name, err)
	}
	return string(b), nil
}

// readGlob concatenates the files matching pattern under dir in name order. Their contents are
// inlined because Include resolves against the embedded CRS, not the disk.
func readGlob(dir, pattern string) (string, error) {
	if dir == "" {
		return "", nil
	}
	paths, err := filepath.Glob(filepath.Join(dir, pattern))
	if err != nil {
		return "", err
	}
	sort.Strings(paths)
	var b strings.Builder
	for _, p := range paths {
		content, err := os.ReadFile(p)
		if err != nil {
			return "", fmt.Errorf("read %s: %w", p, err)
		}
		b.Write(content)
		b.WriteString("\n")
	}
	return b.String(), nil
}

// Verdict is the outcome of inspecting one request.
type Verdict struct {
	Blocked bool
	Event   *Event // nil when the request stayed under the anomaly threshold
}

// Inspect reconstructs the client's request from Traefik's forwardAuth subrequest and runs
// CRS request phases 1 and 2 on it. Response phases never run: forwardAuth sees no response.
func (e *Engine) Inspect(r *http.Request) Verdict {
	e.mu.RLock()
	waf := e.waf
	e.mu.RUnlock()
	tx := waf.NewTransaction()
	defer func() {
		tx.ProcessLogging()
		_ = tx.Close()
	}()

	method := firstNonEmpty(r.Header.Get("X-Forwarded-Method"), r.Method)
	uri := firstNonEmpty(r.Header.Get("X-Forwarded-Uri"), r.URL.RequestURI())
	host := firstNonEmpty(r.Header.Get("X-Forwarded-Host"), r.Host)
	clientIP := e.ClientIP(r)

	tx.ProcessConnection(clientIP, 0, "", 0)
	tx.SetServerName(host)
	tx.ProcessURI(uri, method, r.Proto)
	for name, values := range r.Header {
		if isAuthHopHeader(name) || http.CanonicalHeaderKey(name) == appHeader {
			continue
		}
		for _, v := range values {
			tx.AddRequestHeader(name, v)
		}
	}
	tx.AddRequestHeader("Host", host)
	// The router's opt-in (/check?app=grafana) reaches the app rules as a header only the WAF sets.
	if app := r.URL.Query().Get("app"); app != "" && slices.Contains(e.apps, app) {
		tx.AddRequestHeader(appHeader, app)
	}
	// net/http moves these out of r.Header; without them CRS 920180 flags every POST. forwardAuth
	// delivers the whole body, so its length is known even when it is zero (SignalR's negotiate).
	if r.ContentLength >= 0 && len(r.TransferEncoding) == 0 {
		tx.AddRequestHeader("Content-Length", strconv.FormatInt(r.ContentLength, 10))
	}
	for _, te := range r.TransferEncoding {
		tx.AddRequestHeader("Transfer-Encoding", te)
	}

	interruption := tx.ProcessRequestHeaders()
	if interruption == nil && r.Body != nil {
		if it, _, err := tx.ReadRequestBodyFrom(io.LimitReader(r.Body, 1<<30)); err == nil && it != nil {
			interruption = it
		}
		if interruption == nil {
			if it, err := tx.ProcessRequestBody(); err == nil {
				interruption = it
			}
		}
	}

	event := buildEvent(tx.MatchedRules(), interruption != nil)
	if event != nil {
		event.SourceIP = clientIP
		event.Host = host
		event.Method = method
		event.URI = truncate(uri, 512)
	}
	return Verdict{Blocked: interruption != nil, Event: event}
}

// buildEvent returns an event only when the request crossed the anomaly threshold, which is
// the CRS decision to block. Matches below it are scoring noise, not findings.
func buildEvent(matched []types.MatchedRule, blocked bool) *Event {
	score := 0
	crossed := blocked
	var rules []RuleHit
	for _, m := range matched {
		meta := m.Rule()
		if meta.ID() == inboundAnomalyRuleID {
			crossed = true
			if s := totalScorePattern.FindStringSubmatch(m.Message()); s != nil {
				score, _ = strconv.Atoi(s[1])
			}
			continue
		}
		// Only detection rules: CRS setup rules sit below 910000, scoring rules at 949000 and up.
		if m.Message() == "" || meta.ID() < 910000 || meta.ID() >= 949000 || severityRank(meta.Severity().String()) == 99 {
			continue
		}
		rules = append(rules, RuleHit{
			ID:       meta.ID(),
			Message:  m.Message(),
			Severity: strings.ToUpper(meta.Severity().String()),
			Tags:     meta.Tags(),
			Matched:  matchedData(m.MatchedDatas()),
		})
	}
	if !crossed || len(rules) == 0 {
		return nil
	}
	// Most severe first (CRS severity: lower number is more severe), then by rule ID.
	sort.SliceStable(rules, func(i, j int) bool {
		si, sj := severityRank(rules[i].Severity), severityRank(rules[j].Severity)
		if si != sj {
			return si < sj
		}
		return rules[i].ID < rules[j].ID
	})
	action := ActionDetected
	if blocked {
		action = ActionBlocked
	}
	return &Event{Action: action, AnomalyScore: score, Rules: rules}
}

// Bounds on what an event carries of the request: enough to see why a rule fired, not the request.
const (
	maxMatchedPerRule = 3
	maxMatchedValue   = 200
)

// matchedData is the variable, key, and value each match read, so an exclusion can be written from
// the event instead of guessed.
func matchedData(datas []types.MatchData) []MatchedData {
	var out []MatchedData
	for _, d := range datas {
		if len(out) == maxMatchedPerRule {
			break
		}
		out = append(out, MatchedData{
			Variable: d.Variable().Name(),
			Key:      truncate(d.Key(), maxMatchedValue),
			Value:    truncate(d.Value(), maxMatchedValue),
		})
	}
	return out
}

func severityRank(s string) int {
	if sev, err := types.ParseRuleSeverity(strings.ToLower(s)); err == nil {
		return int(sev)
	}
	return 99
}

// ClientIP is the client of the request Traefik is asking about.
func (e *Engine) ClientIP(r *http.Request) string {
	return clientAddress(r, e.trusted)
}

// clientAddress is the right-most X-Forwarded-For entry that is not a trusted proxy. Never the
// left-most: behind Cloudflare that entry is whatever the client sent, so it is spoofable.
func clientAddress(r *http.Request, trusted []netip.Prefix) string {
	var entries []string
	for _, h := range r.Header.Values("X-Forwarded-For") {
		for _, e := range strings.Split(h, ",") {
			if e = strings.TrimSpace(e); e != "" {
				entries = append(entries, e)
			}
		}
	}
	last := ""
	for i := len(entries) - 1; i >= 0; i-- {
		addr, err := netip.ParseAddr(entries[i])
		if err != nil {
			break // a malformed hop: nothing to its left can be trusted either
		}
		last = addr.Unmap().String()
		if !isTrusted(addr.Unmap(), trusted) {
			return last
		}
	}
	// Every hop is a trusted proxy. forwardAuth sends only the connecting address in
	// X-Forwarded-For, so behind Cloudflare that is the edge; Cloudflare puts the visitor in
	// CF-Connecting-IP and overwrites any value the visitor sent. Read only when the peer is trusted.
	if last != "" {
		if cf, err := netip.ParseAddr(strings.TrimSpace(r.Header.Get("CF-Connecting-IP"))); err == nil {
			return cf.Unmap().String()
		}
		return last
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func isTrusted(addr netip.Addr, trusted []netip.Prefix) bool {
	for _, p := range trusted {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// parseTrusted reads a comma-separated list of IPs and CIDRs, the format of FORWARDED_TRUSTED_IPS.
func parseTrusted(list string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, item := range strings.Split(list, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if !strings.Contains(item, "/") {
			addr, err := netip.ParseAddr(item)
			if err != nil {
				return nil, fmt.Errorf("trusted proxy %q: %w", item, err)
			}
			out = append(out, netip.PrefixFrom(addr.Unmap(), addr.Unmap().BitLen()))
			continue
		}
		p, err := netip.ParsePrefix(item)
		if err != nil {
			return nil, fmt.Errorf("trusted proxy %q: %w", item, err)
		}
		out = append(out, p.Masked())
	}
	return out, nil
}

// Headers Traefik adds for the auth hop itself; the original request never carried them.
func isAuthHopHeader(name string) bool {
	switch http.CanonicalHeaderKey(name) {
	case "X-Forwarded-Method", "X-Forwarded-Uri", "X-Forwarded-Host", "X-Forwarded-Proto",
		"X-Forwarded-Port", "X-Forwarded-Prefix", "X-Forwarded-Server", "X-Real-Ip":
		return true
	}
	return false
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
