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
}

func loadConfig(getenv func(string) string) (config, error) {
	c := config{
		Listen:    envOr(getenv, "WAF_LISTEN", "127.0.0.1:8044"),
		Mode:      strings.ToLower(envOr(getenv, "WAF_MODE", ModeDetect)),
		Token:     getenv("WAF_API_TOKEN"),
		RulesDir:  envOr(getenv, "WAF_RULES_DIR", "/etc/netopt-waf"),
		Paranoia:  1,
		BodyLimit: 10 << 20,
		Capacity:  10000,
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
	return c, nil
}

func envOr(getenv func(string) string, key, fallback string) string {
	if v := getenv(key); v != "" {
		return v
	}
	return fallback
}

func main() {
	healthcheck := flag.Bool("healthcheck", false, "probe /healthz on WAF_LISTEN and exit")
	flag.Parse()

	cfg, err := loadConfig(os.Getenv)
	if err != nil {
		log.Fatal(err)
	}
	if *healthcheck {
		os.Exit(probe(cfg.Listen))
	}

	engine, err := NewEngine(cfg.Mode, cfg.Paranoia, cfg.RulesDir, cfg.BodyLimit)
	if err != nil {
		log.Fatal(err)
	}
	store := NewStore(cfg.Capacity)
	if cfg.Token == "" {
		log.Print("WAF_API_TOKEN is not set: /api/events is disabled, Network Optimizer cannot read events")
	}

	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           newHandler(engine, store, cfg),
		ReadHeaderTimeout: 10 * time.Second,
	}
	log.Printf("netopt-waf listening on %s, mode=%s, paranoia=%d", cfg.Listen, cfg.Mode, cfg.Paranoia)
	log.Fatal(srv.ListenAndServe())
}

func newHandler(engine *Engine, store *Store, cfg config) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/check", func(w http.ResponseWriter, r *http.Request) {
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
		_ = json.NewEncoder(w).Encode(store.Since(since, limit, cfg.Mode, cfg.Paranoia))
	})

	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	return mux
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
