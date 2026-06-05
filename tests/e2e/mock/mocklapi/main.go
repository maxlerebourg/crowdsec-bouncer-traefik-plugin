// Command mocklapi is a minimal Crowdsec LAPI stand-in for the binary e2e
// suite. It answers only the few LAPI routes the plugin calls — live/none
// decision lookups, the stream poll and the usage-metrics push — and lets the
// test drive decisions through /admin instead of `cscli`. It also serves the
// stub upstream that Traefik proxies allowed requests to.
//
// It is deliberately NOT a Crowdsec/AppSec conformance harness: Crowdsec's own
// correctness is the upstream maintainer's responsibility, not this plugin's.
// See the suite README.
package main

import (
	"encoding/json"
	"flag"
	"log"
	"net/http"
	"sync"
)

// Decision is the subset of a LAPI decision the plugin actually reads.
type Decision struct {
	Value    string `json:"value"`
	Type     string `json:"type"`
	Duration string `json:"duration"`
}

var (
	mu      sync.Mutex
	active  = map[string]Decision{} // ip -> decision currently in force
	deleted = map[string]Decision{} // ip -> decision to report in the stream "deleted" list
)

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func list(m map[string]Decision) []Decision {
	out := make([]Decision, 0, len(m))
	for _, d := range m {
		out = append(out, d)
	}
	return out
}

func main() {
	lapiAddr := flag.String("lapi-addr", "127.0.0.1:8090", "address for the LAPI mock")
	// The stub upstream Traefik proxies allowed requests to — the binary-suite
	// equivalent of the traefik/whoami container. Not AppSec.
	backendAddr := flag.String("backend-addr", "127.0.0.1:8091", "address for the stub upstream service")
	flag.Parse()

	go func() {
		log.Fatal(http.ListenAndServe(*backendAddr, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte("E2E_BACKEND_OK\n"))
		})))
	}()

	mux := http.NewServeMux()

	// Readiness probe for the test harness (empty body, 200).
	mux.HandleFunc("/health", func(http.ResponseWriter, *http.Request) {})

	// live / none mode: the plugin asks about one IP and expects a decision
	// array, or the literal `null` when there is none.
	mux.HandleFunc("/v1/decisions", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if d, ok := active[r.URL.Query().Get("ip")]; ok {
			writeJSON(w, []Decision{d})
			return
		}
		_, _ = w.Write([]byte("null"))
	})

	// stream mode: report the whole active set as "new" and anything removed as
	// "deleted". Re-sending the same on every poll is harmless — the plugin just
	// re-adds to / re-deletes from its cache.
	mux.HandleFunc("/v1/decisions/stream", func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		writeJSON(w, map[string][]Decision{"new": list(active), "deleted": list(deleted)})
	})

	// usage-metrics push: accept and ignore.
	mux.HandleFunc("/v1/usage-metrics", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated)
	})

	// Test control plane: add / remove decisions instead of cscli.
	mux.HandleFunc("/admin/decisions", func(_ http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		ip := q.Get("ip")
		mu.Lock()
		defer mu.Unlock()
		switch r.Method {
		case http.MethodPost:
			dtype := q.Get("type")
			if dtype == "" {
				dtype = "ban"
			}
			duration := q.Get("duration")
			if duration == "" {
				duration = "4h"
			}
			active[ip] = Decision{Value: ip, Type: dtype, Duration: duration}
			delete(deleted, ip)
		case http.MethodDelete:
			if d, ok := active[ip]; ok {
				deleted[ip] = d
				delete(active, ip)
			}
		}
	})

	log.Printf("mocklapi: LAPI on %s, backend on %s", *lapiAddr, *backendAddr)
	log.Fatal(http.ListenAndServe(*lapiAddr, mux))
}
