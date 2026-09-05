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
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
)

// Decision is the subset of a LAPI decision the plugin actually reads.
type Decision struct {
	Scope    string `json:"scope"`
	Value    string `json:"value"`
	Type     string `json:"type"`
	Duration string `json:"duration"`
}

var (
	mu      sync.Mutex
	active  = map[string]Decision{} // scope:value -> decision currently in force
	deleted = map[string]Decision{} // scope:value -> decision to report in the stream "deleted" list
)

func decisionKey(scope, value string) string {
	if scope == "" {
		scope = "Ip"
	}
	return strings.ToLower(scope) + ":" + value
}

func ipInRange(ipAddr, cidr string) bool {
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return false
	}
	parsed := net.ParseIP(ipAddr)
	return parsed != nil && network.Contains(parsed)
}

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
// that holds decisions: 1.2.3.4 → "f" (clean), 1.2.3.5 → "t" (banned); any
// other key is a miss ($-1). When verdicts is false it plays the primary and
// answers every GET/MGET with a miss, so a scenario can prove reads are served
// from the replica and not the primary. SET, DEL, AUTH, SELECT get +OK.
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
				writeRedisReply(conn, string(line), verdicts)
			}
		}(conn)
	}
}

func redisBulk(value string) []byte {
	if value == "" {
		return []byte("$-1\r\n")
	}
	return []byte(fmt.Sprintf("$%d\r\n%s\r\n", len(value), value))
}

func redisVerdict(key string, verdicts bool) string {
	if !verdicts {
		return ""
	}
	switch key {
	case "1.2.3.4":
		return "f"
	case "1.2.3.5":
		return "t"
	default:
		return ""
	}
}

func writeRedisReply(conn net.Conn, line string, verdicts bool) {
	fields := strings.Fields(line)
	if len(fields) == 0 {
		_, _ = conn.Write([]byte("+OK\r\n"))
		return
	}
	switch strings.ToUpper(fields[0]) {
	case "GET":
		key := ""
		if len(fields) > 1 {
			key = fields[1]
		}
		_, _ = conn.Write(redisBulk(redisVerdict(key, verdicts)))
	case "MGET":
		keys := fields[1:]
		var body strings.Builder
		fmt.Fprintf(&body, "*%d\r\n", len(keys))
		for _, key := range keys {
			body.Write(redisBulk(redisVerdict(key, verdicts)))
		}
		_, _ = conn.Write([]byte(body.String()))
	default:
		_, _ = conn.Write([]byte("+OK\r\n"))
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
	// cache path. The primary answers every GET/MGET with a miss; the replica
	// serves the hardcoded verdicts, so a scenario pointing redisCacheReadHosts
	// at the replica proves reads are offloaded to replicas.
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

	// live / none mode: ?ip= matches an Ip decision or a covering Range.
	// ?scope=&value= is an exact match (Country, AS, username, …).
	mux.HandleFunc("/v1/decisions", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		q := r.URL.Query()
		if ipAddr := q.Get("ip"); ipAddr != "" {
			if d, ok := active[decisionKey("Ip", ipAddr)]; ok {
				writeJSON(w, []Decision{d})
				return
			}
			for _, d := range active {
				if strings.EqualFold(d.Scope, "Range") && ipInRange(ipAddr, d.Value) {
					writeJSON(w, []Decision{d})
					return
				}
			}
			_, _ = w.Write([]byte("null"))
			return
		}
		if scope := q.Get("scope"); scope != "" {
			if d, ok := active[decisionKey(scope, q.Get("value"))]; ok {
				writeJSON(w, []Decision{d})
				return
			}
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
	// ip= is shorthand for scope=Ip&value=<ip>. scope=&value= is the generic form.
	mux.HandleFunc("/admin/decisions", func(_ http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		scope := q.Get("scope")
		value := q.Get("value")
		if ipAddr := q.Get("ip"); ipAddr != "" {
			scope = "Ip"
			value = ipAddr
		}
		if scope == "" {
			scope = "Ip"
		}
		key := decisionKey(scope, value)
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
			active[key] = Decision{Scope: scope, Value: value, Type: dtype, Duration: duration}
			delete(deleted, key)
		case http.MethodDelete:
			if d, ok := active[key]; ok {
				deleted[key] = d
				delete(active, key)
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
