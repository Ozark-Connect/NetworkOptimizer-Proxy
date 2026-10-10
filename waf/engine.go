package main

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	coreruleset "github.com/corazawaf/coraza-coreruleset/v4"
	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"
)

// CRS rule that fires when the inbound anomaly score crosses the blocking threshold.
const inboundAnomalyRuleID = 949110

var totalScorePattern = regexp.MustCompile(`Total Score: (\d+)`)

// Engine evaluates requests forwarded by Traefik's forwardAuth against Coraza + OWASP CRS.
type Engine struct {
	waf  coraza.WAF
	mode string
}

// NewEngine builds a WAF from the embedded CRS plus optional exclusion files in rulesDir:
// before-crs.conf (runtime ctl exclusions) and after-crs.conf (SecRuleRemoveById and friends).
func NewEngine(mode string, paranoia int, rulesDir string, bodyLimit int) (*Engine, error) {
	engineMode := "DetectionOnly"
	if mode == ModeBlock {
		engineMode = "On"
	}

	before, err := readOptional(rulesDir, "before-crs.conf")
	if err != nil {
		return nil, err
	}
	after, err := readOptional(rulesDir, "after-crs.conf")
	if err != nil {
		return nil, err
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
		before,
		"Include @owasp_crs/*.conf",
		after,
	}, "\n")

	waf, err := coraza.NewWAF(coraza.NewWAFConfig().
		WithRootFS(coreruleset.FS).
		WithDirectives(directives))
	if err != nil {
		return nil, fmt.Errorf("load rules: %w", err)
	}
	return &Engine{waf: waf, mode: mode}, nil
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

// Verdict is the outcome of inspecting one request.
type Verdict struct {
	Blocked bool
	Event   *Event // nil when the request stayed under the anomaly threshold
}

// Inspect reconstructs the client's request from Traefik's forwardAuth subrequest and runs
// CRS request phases 1 and 2 on it. Response phases never run: forwardAuth sees no response.
func (e *Engine) Inspect(r *http.Request) Verdict {
	tx := e.waf.NewTransaction()
	defer func() {
		tx.ProcessLogging()
		_ = tx.Close()
	}()

	method := firstNonEmpty(r.Header.Get("X-Forwarded-Method"), r.Method)
	uri := firstNonEmpty(r.Header.Get("X-Forwarded-Uri"), r.URL.RequestURI())
	host := firstNonEmpty(r.Header.Get("X-Forwarded-Host"), r.Host)
	clientIP := clientAddress(r)

	tx.ProcessConnection(clientIP, 0, "", 0)
	tx.SetServerName(host)
	tx.ProcessURI(uri, method, r.Proto)
	for name, values := range r.Header {
		if isAuthHopHeader(name) {
			continue
		}
		for _, v := range values {
			tx.AddRequestHeader(name, v)
		}
	}
	tx.AddRequestHeader("Host", host)
	// net/http moves these out of r.Header; without them CRS 920180 flags every POST.
	if r.ContentLength > 0 {
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

func severityRank(s string) int {
	if sev, err := types.ParseRuleSeverity(strings.ToLower(s)); err == nil {
		return int(sev)
	}
	return 99
}

// clientAddress is the left-most X-Forwarded-For entry. Traefik rebuilds that header from the
// connection unless the entrypoint trusts an upstream proxy, so the left-most entry is the client.
func clientAddress(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		first := strings.TrimSpace(strings.Split(xff, ",")[0])
		if net.ParseIP(first) != nil {
			return first
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
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
