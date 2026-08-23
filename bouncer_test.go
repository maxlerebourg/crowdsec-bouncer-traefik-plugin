package crowdsec_bouncer_traefik_plugin //nolint:revive,stylecheck

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"text/template"
	"time"

	cache "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/cache"
	configuration "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	ip "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/ip"
	logger "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/logger"
)

func TestServeHTTP(t *testing.T) {
	cfg := CreateConfig()
	cfg.CrowdsecLapiKey = "test"
	cfg.MetricsUpdateIntervalSeconds = 0

	ctx := context.Background()
	next := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {})

	handler, err := New(ctx, next, cfg, "demo-plugin")
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
	if err != nil {
		t.Fatal(err)
	}

	handler.ServeHTTP(recorder, req)
}

func TestNew(t *testing.T) {
	type args struct {
		ctx    context.Context //nolint:containedctx
		next   http.Handler
		config *configuration.Config
		name   string
	}
	tests := []struct {
		name    string
		args    args
		want    http.Handler
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := New(tt.args.ctx, tt.args.next, tt.args.config, tt.args.name)
			if (err != nil) != tt.wantErr {
				t.Errorf("New() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("New() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestBouncer_ServeHTTP(t *testing.T) {
	type fields struct {
		next                   http.Handler
		name                   string
		template               *template.Template
		enabled                bool
		crowdsecScheme         string
		crowdsecHost           string
		crowdsecKey            string
		crowdsecMode           string
		updateInterval         int64
		defaultDecisionTimeout int64
		forwardedCustomHeader  string
		clientPoolStrategy     *ip.PoolStrategy
		serverPoolStrategy     *ip.PoolStrategy
		httpClient             *http.Client
		cacheClient            *cache.Client
	}
	type args struct {
		rw  http.ResponseWriter
		req *http.Request
	}
	tests := []struct {
		name   string
		fields fields
		args   args
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(_ *testing.T) {
			bouncer := &Bouncer{
				next:                   tt.fields.next,
				name:                   tt.fields.name,
				template:               tt.fields.template,
				enabled:                tt.fields.enabled,
				crowdsecScheme:         tt.fields.crowdsecScheme,
				crowdsecHost:           tt.fields.crowdsecHost,
				crowdsecKey:            tt.fields.crowdsecKey,
				crowdsecMode:           tt.fields.crowdsecMode,
				updateInterval:         tt.fields.updateInterval,
				defaultDecisionTimeout: tt.fields.defaultDecisionTimeout,
				forwardedCustomHeader:  tt.fields.forwardedCustomHeader,
				clientPoolStrategy:     tt.fields.clientPoolStrategy,
				serverPoolStrategy:     tt.fields.serverPoolStrategy,
				httpClient:             tt.fields.httpClient,
				cacheClient:            tt.fields.cacheClient,
			}
			bouncer.ServeHTTP(tt.args.rw, tt.args.req)
		})
	}
}

func Test_handleNoStreamCache(t *testing.T) {
	type args struct {
		bouncer  *Bouncer
		remoteIP string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := handleNoStreamCache(tt.args.bouncer, tt.args.remoteIP); (err != nil) != tt.wantErr {
				t.Errorf("handleNoStreamCache() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_handleStreamCache(t *testing.T) {
	type args struct {
		bouncer *Bouncer
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := handleStreamCache(tt.args.bouncer)
			if (err != nil) != tt.wantErr {
				t.Errorf("handleStreamCache() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func Test_streamTickerNeedsRecovery(t *testing.T) {
	elapsed := 10 * time.Minute
	tests := []struct {
		name           string
		lastRun        int64
		updateInterval int64
		want           bool
	}{
		{name: "missing heartbeat", lastRun: 0, updateInterval: 60, want: true},
		{name: "fresh heartbeat", lastRun: int64(elapsed - 119*time.Second), updateInterval: 60, want: false},
		{name: "threshold reached", lastRun: int64(elapsed - 120*time.Second), updateInterval: 60, want: true},
		{name: "stale heartbeat", lastRun: int64(elapsed - 5*time.Minute), updateInterval: 60, want: true},
		{name: "elapsed precedes heartbeat", lastRun: int64(elapsed + time.Second), updateInterval: 60, want: false},
		{name: "invalid interval", lastRun: 0, updateInterval: 0, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := streamTickerNeedsRecovery(tt.lastRun, elapsed, tt.updateInterval); got != tt.want {
				t.Errorf("streamTickerNeedsRecovery() = %v, want %v", got, tt.want)
			}
		})
	}
}

func isolateStreamTestState(t *testing.T, cacheClient *cache.Client) {
	t.Helper()
	previousStartup := atomic.LoadInt32(&isCrowdsecStreamStartup)
	previousHealthy := atomic.LoadInt32(&isCrowdsecStreamHealthy)
	previousUpdateFailure := atomic.LoadInt64(&updateFailure)
	previousLastRun := atomic.LoadInt64(&lastStreamTickerRun)
	cacheClient.Delete(cacheTimeoutKey)
	atomic.StoreInt32(&isCrowdsecStreamStartup, 1)
	atomic.StoreInt32(&isCrowdsecStreamHealthy, 1)
	atomic.StoreInt64(&updateFailure, 0)
	atomic.StoreInt64(&lastStreamTickerRun, 0)
	t.Cleanup(func() {
		cacheClient.Delete(cacheTimeoutKey)
		atomic.StoreInt32(&isCrowdsecStreamStartup, previousStartup)
		atomic.StoreInt32(&isCrowdsecStreamHealthy, previousHealthy)
		atomic.StoreInt64(&updateFailure, previousUpdateFailure)
		atomic.StoreInt64(&lastStreamTickerRun, previousLastRun)
	})
}

func waitForRequest(t *testing.T, requests <-chan int32, want int32) {
	t.Helper()
	select {
	case got := <-requests:
		if got != want {
			t.Fatalf("LAPI request number = %d, want %d", got, want)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for LAPI request %d", want)
	}
}

func markStreamRunStaleForTest(updateInterval int64) {
	threshold := 2 * time.Duration(updateInterval) * time.Second
	if remaining := threshold - time.Since(processStart); remaining >= 0 {
		time.Sleep(remaining + 10*time.Millisecond)
	}
	atomic.StoreInt64(&lastStreamTickerRun, 1)
}

func newStreamTestBouncer(t *testing.T, handler http.Handler, updateInterval int64) (*Bouncer, *httptest.Server) {
	t.Helper()
	lapi := httptest.NewServer(handler)
	lapiURL, err := url.Parse(lapi.URL)
	if err != nil {
		lapi.Close()
		t.Fatal(err)
	}

	log := logger.New("ERROR", "")
	cacheClient := &cache.Client{}
	cacheClient.New(log, false, "", nil, "", "")
	isolateStreamTestState(t, cacheClient)

	return &Bouncer{
		crowdsecMode:        configuration.StreamMode,
		crowdsecScheme:      lapiURL.Scheme,
		crowdsecHost:        lapiURL.Host,
		crowdsecPath:        "/",
		crowdsecKey:         "test",
		crowdsecStreamRoute: crowdsecLapiStreamRoute,
		crowdsecHeader:      crowdsecLapiHeader,
		updateInterval:      updateInterval,
		updateMaxFailure:    0,
		httpClient:          lapi.Client(),
		cacheClient:         cacheClient,
		log:                 log,
	}, lapi
}

func Test_handleStreamTickerContinuesPastWedgedRefresh(t *testing.T) {
	requests := make(chan int32, 4)
	releaseFirst := make(chan struct{})
	var requestCount int32
	bouncer, lapi := newStreamTestBouncer(t, http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		if req.URL.Path != "/v1/decisions/stream" {
			t.Errorf("unexpected LAPI path: %s", req.URL.Path)
		}
		current := atomic.AddInt32(&requestCount, 1)
		requests <- current
		if current == 1 {
			<-releaseFirst
		}
		rw.Header().Set("Content-Type", "application/json")
		_, _ = rw.Write([]byte(`{"deleted":[],"new":[]}`))
	}), 1)
	defer lapi.Close()
	defer close(releaseFirst)

	go handleStreamTicker(bouncer)
	waitForRequest(t, requests, 1)

	// The first refresh remains wedged. Once its one-second cache lease expires,
	// a later tick must still reach LAPI instead of being suppressed by a latch.
	time.Sleep(1100 * time.Millisecond)
	go handleStreamTicker(bouncer)
	waitForRequest(t, requests, 2)

	// The watchdog must retain the same property while the first refresh is
	// still outstanding.
	time.Sleep(1100 * time.Millisecond)
	markStreamRunStaleForTest(bouncer.updateInterval)
	handleStreamWatchdog(bouncer)
	waitForRequest(t, requests, 3)
}

func Test_tickerRuntimeStartsStreamLoopsOnce(t *testing.T) {
	var requests int32
	bouncer, lapi := newStreamTestBouncer(t, http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&requests, 1)
		rw.Header().Set("Content-Type", "application/json")
		_, _ = rw.Write([]byte(`{"deleted":[],"new":[]}`))
	}), 3600)
	defer lapi.Close()

	config := configuration.New()
	config.CrowdsecMode = configuration.StreamMode
	config.UpdateIntervalSeconds = 3600
	config.StreamStartupBlock = true
	config.MetricsUpdateIntervalSeconds = 0

	var runtime tickerRuntime
	defer runtime.stop()
	var wg sync.WaitGroup
	errors := make(chan error, 16)
	// Yaegi v0.16.1 does not support Go 1.22 integer ranges yet.
	//nolint:intrange
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errors <- runtime.startStream(bouncer, config, bouncer.log)
		}()
	}
	wg.Wait()
	close(errors)
	for err := range errors {
		if err != nil {
			t.Fatalf("startStream() error = %v", err)
		}
	}

	if got := atomic.LoadInt32(&requests); got != 1 {
		t.Fatalf("stream initialization made %d LAPI requests, want 1", got)
	}
	if runtime.streamTicker == nil || runtime.streamWatchdogTicker == nil {
		t.Fatal("stream runtime did not retain both ticker stop channels")
	}
}

func Test_handleMetricsTickerDoesNotWaitForStreamRecovery(t *testing.T) {
	streamStarted := make(chan struct{}, 1)
	metricsReported := make(chan struct{}, 1)
	releaseStream := make(chan struct{})
	bouncer, lapi := newStreamTestBouncer(t, http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		switch req.URL.Path {
		case "/v1/decisions/stream":
			streamStarted <- struct{}{}
			<-releaseStream
			rw.Header().Set("Content-Type", "application/json")
			_, _ = rw.Write([]byte(`{"deleted":[],"new":[]}`))
		case "/v1/usage-metrics":
			metricsReported <- struct{}{}
			rw.WriteHeader(http.StatusCreated)
		default:
			t.Errorf("unexpected LAPI path: %s", req.URL.Path)
		}
	}), 1)
	defer lapi.Close()
	defer close(releaseStream)

	previousLastMetricsPush := lastMetricsPush
	defer func() { lastMetricsPush = previousLastMetricsPush }()
	lastMetricsPush = time.Now().Add(-time.Minute)
	markStreamRunStaleForTest(bouncer.updateInterval)
	handleMetricsTicker(bouncer)

	select {
	case <-metricsReported:
	case <-time.After(time.Second):
		t.Fatal("metrics report waited for the forced stream refresh")
	}
	select {
	case <-streamStarted:
	case <-time.After(time.Second):
		t.Fatal("watchdog did not start the asynchronous stream refresh")
	}
}

func Test_crowdsecQuery(t *testing.T) {
	type args struct {
		bouncer   *Bouncer
		stringURL string
		data      []byte
	}
	tests := []struct {
		name    string
		args    args
		want    []byte
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := crowdsecQuery(tt.args.bouncer, tt.args.stringURL, tt.args.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("crowdsecQuery() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("crowdsecQuery() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestHandleBanServeHTTPWithDifferentMethods(t *testing.T) {
	html := "<html>You are banned</html>"
	banTemplate, _ := template.New("html").Delims("{{", "}}").Parse(html)
	tests := []struct {
		name              string
		method            string
		banTemplate       *template.Template
		expectBodyContent bool
	}{
		{
			name:              "GET request should have body with template",
			method:            http.MethodGet,
			banTemplate:       banTemplate,
			expectBodyContent: true,
		},
		{
			name:              "HEAD request should NOT have body even with template",
			method:            http.MethodHead,
			banTemplate:       banTemplate,
			expectBodyContent: false,
		},
		{
			name:              "POST request should have body with template",
			method:            http.MethodPost,
			banTemplate:       banTemplate,
			expectBodyContent: true,
		},
		{
			name:              "PUT request should have body with template",
			method:            http.MethodPut,
			banTemplate:       banTemplate,
			expectBodyContent: true,
		},
		{
			name:              "DELETE request should have body with template",
			method:            http.MethodDelete,
			banTemplate:       banTemplate,
			expectBodyContent: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bouncer := &Bouncer{
				remediationStatusCode:   http.StatusForbidden,
				remediationCustomHeader: "X-Test-Remediation",
				banTemplate:             tt.banTemplate,
				banTemplateContentType:  "text/html; charset=utf-8",
			}

			rw := httptest.NewRecorder()
			req := &http.Request{Method: tt.method}
			bouncer.handleBanServeHTTP(rw, req, "0.0.0.0", "TEST")

			// Check status code
			if rw.Code != http.StatusForbidden {
				t.Errorf("Expected status code 403, got %d", rw.Code)
			}

			// Check custom header
			headerValue := rw.Header().Get("X-Test-Remediation")
			if headerValue != "ban" {
				t.Errorf("Expected header X-Test-Remediation to be 'ban', got %s", headerValue)
			}

			// Check body content
			body := rw.Body.String()
			hasBodyContent := len(body) > 0

			if hasBodyContent != tt.expectBodyContent {
				t.Errorf("Method %s: expected body content: %v, got body content: %v (body: %q)",
					tt.method, tt.expectBodyContent, hasBodyContent, body)
			}

			// If we expect body content, verify it matches template
			if tt.expectBodyContent && body != html {
				t.Errorf("Expected body %q, got %q", html, body)
			}
		})
	}
}

func TestHandleBanServeHTTPContentType(t *testing.T) {
	html := "<html>You are banned</html>"
	banTemplate, _ := template.New("html").Delims("{{", "}}").Parse(html)
	tests := []struct {
		name                   string
		banTemplate            *template.Template
		banTemplateContentType string
	}{
		{
			name:                   "Default HTML content type",
			banTemplate:            banTemplate,
			banTemplateContentType: "text/html; charset=utf-8",
		},
		{
			name:                   "Custom JSON content type",
			banTemplate:            banTemplate,
			banTemplateContentType: "application/json",
		},
		{
			name:                   "Content type set even when banTemplate is nil",
			banTemplate:            nil,
			banTemplateContentType: "application/json",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bouncer := &Bouncer{
				remediationStatusCode:  http.StatusForbidden,
				banTemplate:            tt.banTemplate,
				banTemplateContentType: tt.banTemplateContentType,
			}

			rw := httptest.NewRecorder()
			req := &http.Request{Method: http.MethodGet}
			bouncer.handleBanServeHTTP(rw, req, "0.0.0.0", "TEST")

			if got := rw.Header().Get("Content-Type"); got != tt.banTemplateContentType {
				t.Errorf("Expected Content-Type %q, got %q", tt.banTemplateContentType, got)
			}
		})
	}
}

func TestCaptchaMethodBasedLogic(t *testing.T) {
	tests := []struct {
		name              string
		method            string
		remediation       string
		expectBanFallback bool
	}{
		{
			name:              "GET with captcha remediation should allow captcha",
			method:            http.MethodGet,
			remediation:       cache.CaptchaValue,
			expectBanFallback: false,
		},
		{
			name:              "HEAD with captcha remediation should fallback to ban",
			method:            http.MethodHead,
			remediation:       cache.CaptchaValue,
			expectBanFallback: true,
		},
		{
			name:              "POST with captcha remediation should allow captcha",
			method:            http.MethodPost,
			remediation:       cache.CaptchaValue,
			expectBanFallback: false,
		},
		{
			name:              "PUT with captcha remediation should allow captcha",
			method:            http.MethodPut,
			remediation:       cache.CaptchaValue,
			expectBanFallback: false,
		},
		{
			name:              "DELETE with captcha remediation should allow captcha",
			method:            http.MethodDelete,
			remediation:       cache.CaptchaValue,
			expectBanFallback: false,
		},
		{
			name:              "PATCH with captcha remediation should allow captcha",
			method:            http.MethodPatch,
			remediation:       cache.CaptchaValue,
			expectBanFallback: false,
		},
		{
			name:              "OPTIONS with captcha remediation should allow captcha",
			method:            http.MethodOptions,
			remediation:       cache.CaptchaValue,
			expectBanFallback: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test the core logic: captcha is served for all methods except HEAD
			shouldUseCaptcha := tt.remediation == cache.CaptchaValue && tt.method != http.MethodHead

			if shouldUseCaptcha == tt.expectBanFallback {
				t.Errorf("Method %s with %s remediation: expected ban fallback %v, but logic would use captcha %v",
					tt.method, tt.remediation, tt.expectBanFallback, shouldUseCaptcha)
			}
		})
	}
}

// blockingBody simulates a request body that never reaches EOF, like a
// bidirectional gRPC stream that keeps its body open for the whole life of
// the connection. Reading from it blocks until the test is done.
type blockingBody struct {
	done <-chan struct{}
}

func (b blockingBody) Read(_ []byte) (int, error) {
	<-b.done
	return 0, io.EOF
}

func (blockingBody) Close() error { return nil }

func Test_isBodyUnreadable(t *testing.T) {
	realBody := func() io.ReadCloser { return io.NopCloser(strings.NewReader("data")) }
	tests := []struct {
		name          string
		protoMajor    int
		contentLength int64
		body          io.ReadCloser
		want          bool
	}{
		{name: "http2 grpc stream without content-length", protoMajor: 2, contentLength: -1, body: realBody(), want: true},
		{name: "http3 stream without content-length", protoMajor: 3, contentLength: -1, body: realBody(), want: true},
		{name: "http2 with content-length", protoMajor: 2, contentLength: 42, body: realBody(), want: false},
		{name: "http1.1 chunked without content-length", protoMajor: 1, contentLength: -1, body: realBody(), want: false},
		{name: "http2 without body", protoMajor: 2, contentLength: -1, body: nil, want: false},
		{name: "http2 with http.NoBody", protoMajor: 2, contentLength: -1, body: http.NoBody, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := http.NewRequest(http.MethodPost, "http://localhost", nil)
			req.ProtoMajor = tt.protoMajor
			req.ContentLength = tt.contentLength
			req.Body = tt.body
			if got := isBodyUnreadable(req); got != tt.want {
				t.Errorf("isBodyUnreadable() = %v, want %v", got, tt.want)
			}
		})
	}
}

// newStreamingRequest builds an HTTP/2 request whose body never reaches EOF,
// like a bidirectional gRPC stream (issue #323).
func newStreamingRequest(done <-chan struct{}) *http.Request {
	req, _ := http.NewRequest(http.MethodPost, "http://localhost/signalexchange.SignalExchange/ConnectStream", blockingBody{done: done})
	req.Header.Set("Content-Type", "application/grpc")
	req.ProtoMajor = 2
	req.ContentLength = -1
	return req
}

// Test_appsecQuery_streamingDoesNotBlock is a regression test for issue #323:
// a gRPC streaming request whose body never reaches EOF must not be buffered
// (io.ReadAll would block until timeout and wrongly produce a 403). The appsec
// query must complete promptly, inspecting headers only.
func Test_appsecQuery_streamingDoesNotBlock(t *testing.T) {
	appsecServer := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.WriteHeader(http.StatusOK)
	}))
	defer appsecServer.Close()

	appsecURL, _ := url.Parse(appsecServer.URL)
	bouncer := &Bouncer{
		appsecScheme:           appsecURL.Scheme,
		appsecHost:             appsecURL.Host,
		appsecPath:             "/",
		appsecBodyLimit:        10485760,
		appsecUnreachableBlock: true,
		appsecFailureBlock:     true,
		httpAppsecClient:       appsecServer.Client(),
		log:                    logger.New("INFO", ""),
	}

	done := make(chan struct{})
	defer close(done)

	finished := make(chan error, 1)
	go func() {
		finished <- appsecQuery(bouncer, "1.2.3.4", newStreamingRequest(done))
	}()

	select {
	case err := <-finished:
		if err != nil {
			t.Errorf("appsecQuery() on streaming request returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("appsecQuery() blocked on a streaming request body (issue #323 regression)")
	}
}

// Test_appsecQuery_dropUnreadableBody verifies that, when configured to do so,
// a request with an unreadable body is dropped (blocked) instead of forwarded
// without its body, mirroring the reference APPSEC_DROP_UNREADABLE_BODY option.
func Test_appsecQuery_dropUnreadableBody(t *testing.T) {
	appsecServer := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.WriteHeader(http.StatusOK)
	}))
	defer appsecServer.Close()

	appsecURL, _ := url.Parse(appsecServer.URL)
	bouncer := &Bouncer{
		appsecScheme:              appsecURL.Scheme,
		appsecHost:                appsecURL.Host,
		appsecPath:                "/",
		appsecBodyLimit:           10485760,
		appsecUnreadableBodyBlock: true,
		httpAppsecClient:          appsecServer.Client(),
		log:                       logger.New("INFO", ""),
	}

	done := make(chan struct{})
	defer close(done)

	finished := make(chan error, 1)
	go func() {
		finished <- appsecQuery(bouncer, "1.2.3.4", newStreamingRequest(done))
	}()

	select {
	case err := <-finished:
		if err == nil {
			t.Error("appsecQuery() expected an error to block the request, got nil")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("appsecQuery() blocked on a streaming request body (issue #323 regression)")
	}
}

func newUnreadableGetRequest(done <-chan struct{}) *http.Request {
	req, _ := http.NewRequest(http.MethodGet, "http://localhost/", blockingBody{done: done})
	req.ProtoMajor = 3
	req.ContentLength = -1
	return req
}

// Test_appsecQuery_unreadableBodyGetNotDropped is a regression test for issue #351
func Test_appsecQuery_unreadableBodyGetNotDropped(t *testing.T) {
	appsecServer := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.WriteHeader(http.StatusOK)
	}))
	defer appsecServer.Close()

	appsecURL, _ := url.Parse(appsecServer.URL)
	bouncer := &Bouncer{
		appsecScheme:              appsecURL.Scheme,
		appsecHost:                appsecURL.Host,
		appsecPath:                "/",
		appsecBodyLimit:           10485760,
		appsecUnreadableBodyBlock: true,
		httpAppsecClient:          appsecServer.Client(),
		log:                       logger.New("INFO", ""),
	}

	done := make(chan struct{})
	defer close(done)

	finished := make(chan error, 1)
	go func() {
		finished <- appsecQuery(bouncer, "1.2.3.4", newUnreadableGetRequest(done))
	}()

	select {
	case err := <-finished:
		if err != nil {
			t.Errorf("appsecQuery() on an HTTP/3 GET without content-length returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("appsecQuery() blocked on an HTTP/3 GET request body (issue #351 regression)")
	}
}
