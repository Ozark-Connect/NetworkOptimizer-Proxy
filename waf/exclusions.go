package main

import (
	"embed"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
)

// Built-in exclusion sets for self-hosted apps CRS has no plugin for, one file per app.
//
//go:embed apps/*.conf
var appFiles embed.FS

// AppNames lists the built-in exclusion sets, sorted.
func AppNames() []string {
	entries, _ := appFiles.ReadDir("apps")
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, strings.TrimSuffix(e.Name(), ".conf"))
	}
	sort.Strings(names)
	return names
}

// parseApps reads WAF_APP_EXCLUSIONS: empty means every built-in set, "none" means none.
func parseApps(v string) ([]string, error) {
	v = strings.TrimSpace(strings.ToLower(v))
	if v == "" {
		return AppNames(), nil
	}
	if v == "none" {
		return nil, nil
	}
	known := map[string]bool{}
	for _, n := range AppNames() {
		known[n] = true
	}
	var out []string
	for _, n := range strings.Split(v, ",") {
		if n = strings.TrimSpace(n); n == "" {
			continue
		}
		if !known[n] {
			return nil, fmt.Errorf("unknown app %q (built-in: %s, or none)", n, strings.Join(AppNames(), ", "))
		}
		out = append(out, n)
	}
	return out, nil
}

func appDirectives(names []string) string {
	var b strings.Builder
	for _, n := range names {
		data, err := appFiles.ReadFile("apps/" + n + ".conf")
		if err != nil {
			continue // parseApps only passes known names
		}
		b.Write(data)
		b.WriteString("\n")
	}
	return b.String()
}

// maxExclusions bounds a PUT; managed exclusions take rule IDs 2000 to 2000+maxExclusions-1.
const maxExclusions = 1000

var (
	hostPattern   = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$`)
	pathPattern   = regexp.MustCompile(`^/[A-Za-z0-9\-._~!$&'()*+,;=:@/%]*$`)
	allowedMethod = map[string]bool{"GET": true, "HEAD": true, "POST": true, "PUT": true, "PATCH": true, "DELETE": true, "OPTIONS": true}
)

// Exclusion turns one CRS rule off for requests matching every field that is set. Network
// Optimizer sends these structured; the WAF writes the SecLang, so no rule text crosses the API.
type Exclusion struct {
	ID     string `json:"id"`
	RuleID int    `json:"ruleId"`
	Host   string `json:"host,omitempty"`
	Method string `json:"method,omitempty"`
	Path   string `json:"path,omitempty"` // a path prefix, without the query string
}

func (x *Exclusion) normalize() error {
	x.Host = strings.ToLower(strings.TrimSpace(x.Host))
	x.Method = strings.ToUpper(strings.TrimSpace(x.Method))
	x.Path = strings.TrimSpace(x.Path)
	if len(x.ID) > 64 {
		return fmt.Errorf("id is longer than 64 characters")
	}
	if x.RuleID < 900000 || x.RuleID > 999999 {
		return fmt.Errorf("rule %d is not a CRS rule ID (900000-999999)", x.RuleID)
	}
	if x.Host == "" && x.Path == "" {
		return fmt.Errorf("rule %d: set a host or a path; turn a rule off everywhere in after-crs.conf", x.RuleID)
	}
	if x.Host != "" && (len(x.Host) > 253 || !hostPattern.MatchString(x.Host)) {
		return fmt.Errorf("host %q is not a host name", x.Host)
	}
	if x.Method != "" && !allowedMethod[x.Method] {
		return fmt.Errorf("method %q is not supported", x.Method)
	}
	if x.Path != "" && (len(x.Path) > 512 || !pathPattern.MatchString(x.Path)) {
		return fmt.Errorf("path %q must start with / and hold only URL path characters", x.Path)
	}
	return nil
}

// renderExclusions writes runtime ctl exclusions, one chain per entry, in a reserved ID range.
func renderExclusions(list []Exclusion) string {
	var b strings.Builder
	for i, x := range list {
		var links []string
		if x.Host != "" {
			// Host may carry a port; the name is validated, so only its dots need escaping.
			links = append(links, fmt.Sprintf(`SecRule REQUEST_HEADERS:Host "@rx ^%s(?::\d+)?$"`, strings.ReplaceAll(x.Host, ".", `\.`)))
		}
		if x.Method != "" {
			links = append(links, fmt.Sprintf(`SecRule REQUEST_METHOD "@streq %s"`, x.Method))
		}
		if x.Path != "" {
			links = append(links, fmt.Sprintf(`SecRule REQUEST_FILENAME "@beginsWith %s"`, x.Path))
		}
		remove := fmt.Sprintf("ctl:ruleRemoveById=%d", x.RuleID)
		for j, link := range links {
			var actions []string
			if j == 0 {
				actions = append(actions, fmt.Sprintf("id:%d,phase:1,pass,nolog", 2000+i))
				if x.Host != "" {
					actions = append(actions, "t:lowercase")
				}
			}
			if j < len(links)-1 {
				actions = append(actions, "chain")
			} else {
				actions = append(actions, remove)
			}
			fmt.Fprintf(&b, "%s \"%s\"\n", link, strings.Join(actions, ","))
		}
	}
	return b.String()
}

// ExclusionStore keeps the managed exclusions, saved in the state directory when one is set.
type ExclusionStore struct {
	mu   sync.Mutex
	dir  string
	list []Exclusion
}

// NewExclusionStore loads saved exclusions; entries that no longer validate are dropped.
func NewExclusionStore(dir string) (*ExclusionStore, error) {
	s := &ExclusionStore{dir: dir}
	if dir == "" {
		return s, nil
	}
	data, err := os.ReadFile(s.path())
	if os.IsNotExist(err) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	var saved []Exclusion
	if err := json.Unmarshal(data, &saved); err != nil {
		return nil, fmt.Errorf("%s: %w", s.path(), err)
	}
	s.list, _ = validateExclusions(saved)
	return s, nil
}

func (s *ExclusionStore) path() string { return filepath.Join(s.dir, "exclusions.json") }

// List returns the managed exclusions.
func (s *ExclusionStore) List() []Exclusion {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Exclusion{}, s.list...)
}

// Save records list, which the caller has validated and built.
func (s *ExclusionStore) Save(list []Exclusion) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.list = append([]Exclusion{}, list...)
	if s.dir == "" {
		return nil
	}
	data, err := json.Marshal(s.list)
	if err != nil {
		return err
	}
	tmp := s.path() + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path())
}

// validateExclusions normalizes every entry and returns the first error, keeping the valid ones.
func validateExclusions(list []Exclusion) ([]Exclusion, error) {
	if len(list) > maxExclusions {
		return nil, fmt.Errorf("at most %d exclusions, got %d", maxExclusions, len(list))
	}
	out := make([]Exclusion, 0, len(list))
	var first error
	for _, x := range list {
		if err := x.normalize(); err != nil {
			if first == nil {
				first = err
			}
			continue
		}
		out = append(out, x)
	}
	return out, first
}
