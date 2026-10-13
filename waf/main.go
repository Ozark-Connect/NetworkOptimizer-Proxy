// Command netopt-waf is a Coraza + OWASP CRS web application firewall that Traefik calls through
// its forwardAuth middleware. It answers 200 (allow) or 403 (block) and keeps the requests that
// crossed the CRS anomaly threshold for Network Optimizer to read from /api/events.
package main

import (
	"crypto/subtle"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"
)

// WAF modes.
const (
	ModeDetect = "detect"
	ModeBlock  = "block"
)

type config struct {
	Listen    string
	Mode      string
	Paranoia  int
	Token     string
	RulesDir  string
	BodyLimit int
	Capacity  int
	Trusted   []netip.Prefix
	StateDir  string
	Methods   string
}

func loadConfig(getenv func(string) string) (config, error) {
	c := config{
		Listen:    envOr(getenv, "WAF_LISTEN", "127.0.0.1:8044"),
		Mode:      strings.ToLower(envOr(getenv, "WAF_MODE", ModeDetect)),
		Token:     getenv("WAF_API_TOKEN"),
		RulesDir:  envOr(getenv, "WAF_RULES_DIR", "/etc/netopt-waf"),
		StateDir:  getenv("WAF_STATE_DIR"),
		Paranoia:  1,
		BodyLimit: 10 << 20,
		Capacity:  10000,
		Methods:   DefaultAllowedMethods,
	}
	if c.Mode != ModeDetect && c.Mode != ModeBlock {
		return c, fmt.Errorf("WAF_MODE must be %q or %q, got %q", ModeDetect, ModeBlock, c.Mode)
	}
	if v := getenv("WAF_PARANOIA"); v != "" {
		p, err := strconv.Atoi(v)
		if err != nil || p < 1 || p > 4 {
			return c, fmt.Errorf("WAF_PARANOIA must be 1-4, got %q", v)
		}
		c.Paranoia = p
	}
	if v := getenv("WAF_BODY_LIMIT"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			return c, fmt.Errorf("WAF_BODY_LIMIT must be a positive byte count, got %q", v)
		}
		c.BodyLimit = n
	}
	if v := getenv("WAF_ALLOWED_METHODS"); v != "" {
		methods, err := parseMethods(v)
		if err != nil {
			return c, fmt.Errorf("WAF_ALLOWED_METHODS: %w", err)
		}
		c.Methods = methods
	}
	trusted, err := parseTrusted(getenv("WAF_TRUSTED_PROXIES"))
	if err != nil {
		return c, fmt.Errorf("WAF_TRUSTED_PROXIES: %w", err)
	}
	c.Trusted = trusted
	return c, nil
}

// parseMethods takes methods separated by spaces or commas and returns them upper-cased and
// space-separated. Only letters pass, so the value cannot break out of the CRS setvar.
func parseMethods(v string) (string, error) {
	fields := strings.FieldsFunc(v, func(r rune) bool { return r == ' ' || r == ',' })
	if len(fields) == 0 {
		return "", fmt.Errorf("no methods in %q", v)
	}
	for i, f := range fields {
		f = strings.ToUpper(f)
		for _, r := range f {
			if r < 'A' || r > 'Z' {
				return "", fmt.Errorf("%q is not a method name", fields[i])
			}
		}
		fields[i] = f
	}
	return strings.Join(fields, " "), nil
}

func envOr(getenv func(string) string, key, fallback string) string {
	if v := getenv(key); v != "" {
		return v
	}
	return fallback
}

func main() {
	healthcheck := flag.Bool("healthcheck", false, "probe /healthz on WAF_LISTEN and exit")
	showVersion := flag.Bool("version", false, "print the netopt-waf and CRS versions and exit")
	flag.Parse()
	if *showVersion {
		fmt.Printf("netopt-waf %s (CRS %s)\n", Version, CRSVersion)
		return
	}

	cfg, err := loadConfig(os.Getenv)
	if err != nil {
		log.Fatal(err)
	}
	if *healthcheck {
		os.Exit(probe(cfg.Listen))
	}

	// A mode set from Network Optimizer is saved and wins; WAF_MODE is only the starting mode.
	modes, err := NewModeStore(cfg.StateDir, cfg.Mode, time.Now())
	if err != nil {
		log.Fatal(err)
	}
	exclusions, err := NewExclusionStore(cfg.StateDir)
	if err != nil {
		log.Fatal(err)
	}
	engine, err := NewEngine(modes.Get().Mode, cfg.Paranoia, cfg.RulesDir, cfg.BodyLimit, cfg.Trusted,
		WithExclusions(exclusions.List()), WithAllowedMethods(cfg.Methods))
	if err != nil {
		log.Fatal(err)
	}
	store := NewStore(cfg.Capacity)
	allow, err := NewAllowLists(cfg.StateDir)
	if err != nil {
		log.Fatal(err)
	}
	if cfg.Token == "" {
		log.Print("WAF_API_TOKEN is not set: the API is disabled, so Network Optimizer cannot read events or push its lists")
	}

	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           newHandler(engine, store, NewBanList(), allow, modes, exclusions, cfg),
		ReadHeaderTimeout: 10 * time.Second,
	}
	log.Printf("netopt-waf %s (CRS %s) listening on %s, mode=%s, paranoia=%d, methods=%s, trusted proxies=%d",
		Version, CRSVersion, cfg.Listen, engine.Mode(), cfg.Paranoia, cfg.Methods, len(cfg.Trusted))
	log.Fatal(srv.ListenAndServe())
}

func newHandler(engine *Engine, store *Store, bans *BanList, allow *AllowLists, modes *ModeStore, exclusions *ExclusionStore, cfg config) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/check", func(w http.ResponseWriter, r *http.Request) {
		client := engine.ClientIP(r)
		// A route that names an allow list (/check?allow=trusted) takes only its members and LAN
		// sources. Like bans, this applies in detect mode: it is the operator's decision, not a rule match.
		if name := r.URL.Query().Get("allow"); name != "" && !allow.Allowed(name, client) {
			store.RecordNotAllowed()
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		// Bans apply in detect mode too: they are Network Optimizer's decision, not a rule match.
		if bans.Banned(client) {
			store.RecordBanned()
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		v := engine.Inspect(r)
		store.Record(v)
		if v.Event != nil {
			if line, err := json.Marshal(v.Event); err == nil {
				log.Printf("event %s", line)
			}
		}
		if v.Blocked {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	mux.HandleFunc("GET /api/events", func(w http.ResponseWriter, r *http.Request) {
		if !authorized(r, cfg.Token) {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		since, _ := strconv.ParseUint(r.URL.Query().Get("since"), 10, 64)
		limit := 500
		if l, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && l > 0 && l < limit {
			limit = l
		}
		w.Header().Set("Content-Type", "application/json")
		page := store.Since(since, limit, engine.Mode(), cfg.Paranoia)
		page.ModeSince = modes.Get().Since
		page.Version, page.CRS = Version, CRSVersion
		_ = json.NewEncoder(w).Encode(page)
	})

	mux.HandleFunc("GET /api/bans", func(w http.ResponseWriter, r *http.Request) {
		if !authorized(r, cfg.Token) {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(bans.List())
	})

	// PUT replaces the whole list; Network Optimizer sends its full desired set every sync.
	mux.HandleFunc("PUT /api/bans", func(w http.ResponseWriter, r *http.Request) {
		if !authorized(r, cfg.Token) {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		var body struct {
			Bans []Ban `json:"bans"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<20)).Decode(&body); err != nil {
			http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
			return
		}
		if err := bans.Replace(body.Bans); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(bans.List())
	})

	mux.HandleFunc("GET /api/mode", func(w http.ResponseWriter, r *http.Request) {
		if !authorized(r, cfg.Token) {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(modes.Get())
	})

	// PUT switches between detect and block. The new rules engine is built before the old one is
	// replaced, so a failed build leaves the mode unchanged.
	mux.HandleFunc("PUT /api/mode", func(w http.ResponseWriter, r *http.Request) {
		if !authorized(r, cfg.Token) {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		var body struct {
			Mode string `json:"mode"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&body); err != nil {
			http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
			return
		}
		if err := engine.SetMode(body.Mode); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		state, err := modes.Set(body.Mode, time.Now())
		if err != nil {
			http.Error(w, "mode changed but not saved: "+err.Error(), http.StatusInternalServerError)
			return
		}
		log.Printf("mode set to %s by the API", body.Mode)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(state)
	})

	mux.HandleFunc("GET /api/allowlists", func(w http.ResponseWriter, r *http.Request) {
		if !authorized(r, cfg.Token) {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(allow.List())
	})

	// PUT replaces one list whole; Network Optimizer sends its Trusted Sources as "trusted" every sync.
	mux.HandleFunc("PUT /api/allowlists/{name}", func(w http.ResponseWriter, r *http.Request) {
		if !authorized(r, cfg.Token) {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		var body struct {
			Entries []string `json:"entries"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<20)).Decode(&body); err != nil {
			http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
			return
		}
		if err := allow.Replace(r.PathValue("name"), body.Entries); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(allow.List())
	})

	mux.HandleFunc("GET /api/exclusions", func(w http.ResponseWriter, r *http.Request) {
		if !authorized(r, cfg.Token) {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		writeExclusions(w, engine, exclusions)
	})

	// PUT replaces the managed exclusions whole. The new set is built before it is saved or swapped
	// in, so an entry that fails to build leaves the running rules and the saved set unchanged.
	mux.HandleFunc("PUT /api/exclusions", func(w http.ResponseWriter, r *http.Request) {
		if !authorized(r, cfg.Token) {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		var body struct {
			Exclusions []Exclusion `json:"exclusions"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body); err != nil {
			http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
			return
		}
		list, err := validateExclusions(body.Exclusions)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := engine.SetExclusions(list); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := exclusions.Save(list); err != nil {
			http.Error(w, "exclusions applied but not saved: "+err.Error(), http.StatusInternalServerError)
			return
		}
		log.Printf("%d managed exclusions set by the API", len(list))
		writeExclusions(w, engine, exclusions)
	})

	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	return mux
}

// writeExclusions answers with the built-in app sets in use and the managed exclusions.
func writeExclusions(w http.ResponseWriter, engine *Engine, exclusions *ExclusionStore) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(struct {
		Apps       []string    `json:"apps"`
		Exclusions []Exclusion `json:"exclusions"`
	}{engine.Apps(), exclusions.List()})
}

// authorized requires "Authorization: Bearer <token>"; an unset token disables the API.
func authorized(r *http.Request, token string) bool {
	if token == "" {
		return false
	}
	got, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	return ok && subtle.ConstantTimeCompare([]byte(got), []byte(token)) == 1
}

func probe(listen string) int {
	host := listen
	if strings.HasPrefix(host, "0.0.0.0:") || strings.HasPrefix(host, ":") {
		host = "127.0.0.1:" + host[strings.LastIndex(host, ":")+1:]
	}
	client := http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get("http://" + host + "/healthz")
	if err != nil || resp.StatusCode != http.StatusOK {
		return 1
	}
	_ = resp.Body.Close()
	return 0
}
