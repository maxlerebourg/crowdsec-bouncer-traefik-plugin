// Command mocklapi is a minimal Crowdsec LAPI mock for the binary e2e suite.
//
// It speaks just enough of the LAPI HTTP contract for the plugin to exercise
// its own logic — live/none queries, the stream delta protocol and the
// usage-metrics push — without running a real Crowdsec. Decisions are driven
// from the test via the /admin endpoints instead of `cscli`.
//
// This is deliberately NOT a Crowdsec/AppSec conformance harness: validating
// that Crowdsec or its AppSec engine behave correctly is the upstream
// maintainer's responsibility, not this plugin's. See the suite README.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"sync"
)

const lapiKeyHeader = "X-Api-Key"

// Decision mirrors the subset of the LAPI decision object the plugin reads.
type Decision struct {
	ID       int    `json:"id"`
	Origin   string `json:"origin"`
	Type     string `json:"type"`
	Scope    string `json:"scope"`
	Value    string `json:"value"`
	Duration string `json:"duration"`
	Scenario string `json:"scenario"`
}

// store holds the active decisions and the stream delta bookkeeping.
type store struct {
	mu        sync.Mutex
	decisions map[string]Decision
	streamed  map[string]struct{} // values already advertised to the stream consumer
	nextID    int
}

func newStore() *store {
	return &store{
		decisions: map[string]Decision{},
		streamed:  map[string]struct{}{},
		nextID:    1,
	}
}

func (s *store) add(ip, dtype, duration string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.decisions[ip] = Decision{
		ID:       s.nextID,
		Origin:   "cscli",
		Type:     dtype,
		Scope:    "Ip",
		Value:    ip,
		Duration: duration,
		Scenario: "e2e",
	}
	s.nextID++
}

func (s *store) delete(ip string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.decisions, ip)
}

func (s *store) reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.decisions = map[string]Decision{}
	s.streamed = map[string]struct{}{}
}

func (s *store) get(ip string) (Decision, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	d, ok := s.decisions[ip]
	return d, ok
}

// stream computes the new/deleted delta since the last poll. On startup the
// consumer expects the full current set as "new".
func (s *store) stream(startup bool) map[string][]Decision {
	s.mu.Lock()
	defer s.mu.Unlock()
	newd := []Decision{}
	deleted := []Decision{}
	for ip, d := range s.decisions {
		if startup {
			newd = append(newd, d)
			continue
		}
		if _, seen := s.streamed[ip]; !seen {
			newd = append(newd, d)
		}
	}
	if !startup {
		for ip := range s.streamed {
			if _, active := s.decisions[ip]; !active {
				deleted = append(deleted, Decision{Value: ip, Scope: "Ip", Type: "ban"})
			}
		}
	}
	s.streamed = map[string]struct{}{}
	for ip := range s.decisions {
		s.streamed[ip] = struct{}{}
	}
	return map[string][]Decision{"new": newd, "deleted": deleted}
}

func writeJSON(w http.ResponseWriter, code int, payload any) {
	body, _ := json.Marshal(payload)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_, _ = w.Write(body)
}

func lapiHandler(s *store, apiKey string) http.Handler {
	mux := http.NewServeMux()

	authorized := func(r *http.Request) bool {
		return r.Header.Get(lapiKeyHeader) == apiKey
	}

	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})

	mux.HandleFunc("/v1/decisions/stream", func(w http.ResponseWriter, r *http.Request) {
		if !authorized(r) {
			writeJSON(w, http.StatusForbidden, map[string]string{"message": "access forbidden"})
			return
		}
		startup := r.URL.Query().Get("startup") == "true"
		writeJSON(w, http.StatusOK, s.stream(startup))
	})

	mux.HandleFunc("/v1/decisions", func(w http.ResponseWriter, r *http.Request) {
		if !authorized(r) {
			writeJSON(w, http.StatusForbidden, map[string]string{"message": "access forbidden"})
			return
		}
		ip := r.URL.Query().Get("ip")
		if d, ok := s.get(ip); ok {
			writeJSON(w, http.StatusOK, []Decision{d})
			return
		}
		// LAPI returns the literal `null` when no decision matches.
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("null"))
	})

	mux.HandleFunc("/v1/usage-metrics", func(w http.ResponseWriter, r *http.Request) {
		// Accept and ignore — we only assert the plugin can push without erroring.
		if !authorized(r) {
			writeJSON(w, http.StatusForbidden, map[string]string{"message": "access forbidden"})
			return
		}
		writeJSON(w, http.StatusCreated, map[string]string{"message": "ok"})
	})

	mux.HandleFunc("/admin/decisions", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		ip := q.Get("ip")
		switch r.Method {
		case http.MethodPost:
			if ip == "" {
				writeJSON(w, http.StatusBadRequest, map[string]string{"message": "missing ip"})
				return
			}
			dtype := q.Get("type")
			if dtype == "" {
				dtype = "ban"
			}
			duration := q.Get("duration")
			if duration == "" {
				duration = "4h"
			}
			s.add(ip, dtype, duration)
			writeJSON(w, http.StatusOK, map[string]string{"message": "added", "ip": ip, "type": dtype})
		case http.MethodDelete:
			s.delete(ip)
			writeJSON(w, http.StatusOK, map[string]string{"message": "deleted", "ip": ip})
		default:
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"message": "method not allowed"})
		}
	})

	mux.HandleFunc("/admin/reset", func(w http.ResponseWriter, _ *http.Request) {
		s.reset()
		writeJSON(w, http.StatusOK, map[string]string{"message": "reset"})
	})

	return mux
}

func backendHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("X-E2E-Backend", "ok")
		w.WriteHeader(http.StatusOK)
		if r.Method != http.MethodHead {
			_, _ = w.Write([]byte("E2E_BACKEND_OK\n"))
		}
	})
}

func main() {
	lapiAddr := flag.String("lapi-addr", "127.0.0.1:8090", "address for the LAPI mock")
	// The stub upstream service Traefik proxies allowed requests to — the
	// binary-suite equivalent of the traefik/whoami container. Not AppSec.
	backendAddr := flag.String("backend-addr", "127.0.0.1:8091", "address of the stub upstream service Traefik proxies allowed requests to")
	apiKey := flag.String("api-key", "e2e-mock-key", "expected X-Api-Key value")
	flag.Parse()

	s := newStore()

	go func() {
		if err := http.ListenAndServe(*backendAddr, backendHandler()); err != nil {
			log.Fatalf("backend: %v", err)
		}
	}()

	fmt.Printf("mocklapi: LAPI on %s, backend on %s\n", *lapiAddr, *backendAddr)
	if err := http.ListenAndServe(*lapiAddr, lapiHandler(s, *apiKey)); err != nil {
		log.Fatalf("lapi: %v", err)
	}
}
