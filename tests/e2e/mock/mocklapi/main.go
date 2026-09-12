// Command mocklapi is a minimal Crowdsec LAPI stand-in for the binary e2e
// suite. It answers only the few LAPI routes the plugin calls — live/none
// decision lookups, the stream poll and the usage-metrics push — and lets the
// test drive decisions through /admin instead of `cscli`. It also serves the
// stub upstream that Traefik proxies allowed requests to, and a hardcoded Redis
// stand-in for exercising the redis cache path.
//
// It is NOT a Crowdsec/AppSec conformance harness — the real WAF engine (OWASP
// CRS, virtual patching) is out of scope. The AppSec endpoint here emulates a
// single deterministic rule so the suite can exercise the plugin's AppSec
// wiring (header forwarding, allow/block handling) end to end. See the README.
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
)

// Decision is the subset of a LAPI decision the plugin actually reads.
type Decision struct {
	Value    string `json:"value"`
	Type     string `json:"type"`
	Duration string `json:"duration"`
	Origin   string `json:"origin"`
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

// --- Redis mock (inline-command wire format, as spoken by simpleredis) ---

// serveRedis is a hardcoded stand-in. When verdicts is true it plays a replica
// that holds decisions: every line is scanned for known IPs, 1.2.3.4 → "f"
// (clean), 1.2.3.5 → "t" (banned); any other GET is a miss ($-1). When verdicts
// is false it plays the primary and answers every GET with a miss, so a
// scenario can prove reads are served from the replica and not the primary.
// SET, DEL, AUTH, SELECT get +OK (they don't read the response anyway).
func serveRedis(addr string, verdicts bool) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatal(err)
	}
	defer ln.Close()

	for {
		conn, err := ln.Accept()
		if err != nil {
			continue
		}
		go func(conn net.Conn) {
			defer conn.Close()
			rd := bufio.NewReader(conn)
			for {
				line, _, err := rd.ReadLine()
				if err != nil {
					return
				}
				s := string(line)
				switch {
				case verdicts && strings.Contains(s, "1.2.3.4"):
					conn.Write([]byte("$1\r\nf\r\n"))
				case verdicts && strings.Contains(s, "1.2.3.5"):
					conn.Write([]byte("$1\r\nt\r\n"))
				case strings.HasPrefix(strings.ToUpper(s), "GET "):
					conn.Write([]byte("$-1\r\n"))
				default:
					conn.Write([]byte("+OK\r\n"))
				}
			}
		}(conn)
	}
}

func main() {
	lapiAddr := flag.String("lapi-addr", "127.0.0.1:8090", "address for the LAPI mock")
	// The stub upstream Traefik proxies allowed requests to — the binary-suite
	// equivalent of the traefik/whoami container. Not AppSec.
	backendAddr := flag.String("backend-addr", "127.0.0.1:8091", "address for the stub upstream service")
	// AppSec WAF stand-in (the real engine listens on :7422). Not a CRS engine.
	appsecAddr := flag.String("appsec-addr", "127.0.0.1:8092", "address for the AppSec mock")
	// Redis stand-ins on plain TCP ports, enough to exercise the plugin's redis
	// cache path. The primary answers every GET with a miss; the replica serves
	// the hardcoded verdicts, so a scenario pointing redisCacheReadHosts at the
	// replica proves reads are offloaded to replicas.
	redisAddr := flag.String("redis-addr", "127.0.0.1:8093", "address for the Redis primary mock (writes; GET always misses)")
	redisReadAddr := flag.String("redis-read-addr", "127.0.0.1:8094", "address for the Redis replica mock (serves cached verdicts)")
	// Optional TLS for the LAPI: when both are set the LAPI is served over HTTPS
	// (cert signed by the scenario's throwaway CA) so the suite can exercise the
	// bouncer's system-trust-store path. Backend and AppSec stay plaintext.
	lapiTLSCert := flag.String("lapi-tls-cert", "", "PEM cert to serve the LAPI over HTTPS (optional)")
	lapiTLSKey := flag.String("lapi-tls-key", "", "PEM key for --lapi-tls-cert")
	flag.Parse()

	go func() {
		log.Fatal(http.ListenAndServe(*backendAddr, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte("E2E_BACKEND_OK\n"))
		})))
	}()

	// AppSec mock: the plugin forwards the request metadata in X-Crowdsec-Appsec-*
	// headers and reads our status — 200 allows, 403 blocks. We emulate one
	// deterministic virtual-patching rule (block any URI containing "rpc2", the
	// exact probe from examples/appsec-enabled) so the plugin's AppSec path is
	// exercised without standing up the real WAF.
	go func() {
		log.Fatal(http.ListenAndServe(*appsecAddr, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.Contains(r.Header.Get("X-Crowdsec-Appsec-Uri"), "403") {
				w.WriteHeader(http.StatusForbidden)
			}
			if strings.Contains(r.Header.Get("X-Crowdsec-Appsec-Uri"), "500") {
				w.WriteHeader(http.StatusInternalServerError)
			}
			if strings.Contains(r.Header.Get("X-Crowdsec-Appsec-Uri"), "502") {
				w.WriteHeader(http.StatusBadGateway)
			}
			// Read body
			body, err := io.ReadAll(r.Body)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			defer r.Body.Close()
			if strings.Contains(string(body), "a=0") {
				w.WriteHeader(http.StatusForbidden)
				return
			}
		})))
	}()

	go serveRedis(*redisAddr, false)
	go serveRedis(*redisReadAddr, true)

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
			origin := q.Get("origin")
			if origin == "" {
				origin = "crowdsec"
			}
			active[ip] = Decision{Value: ip, Type: dtype, Duration: duration, Origin: origin}
			delete(deleted, ip)
		case http.MethodDelete:
			if d, ok := active[ip]; ok {
				deleted[ip] = d
				delete(active, ip)
			}
		}
	})

	if *lapiTLSCert != "" && *lapiTLSKey != "" {
		log.Printf("mocklapi: LAPI on %s (TLS), backend on %s, appsec on %s, redis on %s (read %s)", *lapiAddr, *backendAddr, *appsecAddr, *redisAddr, *redisReadAddr)
		log.Fatal(http.ListenAndServeTLS(*lapiAddr, *lapiTLSCert, *lapiTLSKey, mux))
	}
	log.Printf("mocklapi: LAPI on %s, backend on %s, appsec on %s, redis on %s (read %s)", *lapiAddr, *backendAddr, *appsecAddr, *redisAddr, *redisReadAddr)
	log.Fatal(http.ListenAndServe(*lapiAddr, mux))
}
