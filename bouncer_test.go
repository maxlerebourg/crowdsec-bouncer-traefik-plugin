package crowdsec_bouncer_traefik_plugin

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"text/template"

	configuration "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	ip "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/ip"
)

func TestServeHTTP(t *testing.T) {
	cfg := CreateConfig()
	cfg.CrowdsecLapiKey = "test"

	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {})

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
		ctx    context.Context
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
		customHeader           string
		clientPoolStrategy     *ip.PoolStrategy
		serverPoolStrategy     *ip.PoolStrategy
		client                 *http.Client
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
		t.Run(tt.name, func(t *testing.T) {
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
				customHeader:           tt.fields.customHeader,
				clientPoolStrategy:     tt.fields.clientPoolStrategy,
				serverPoolStrategy:     tt.fields.serverPoolStrategy,
				client:                 tt.fields.client,
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
			if err := handleNoStreamCache(tt.args.bouncer, tt.args.remoteIP); (err != nil) != tt.wantErr {
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
		name string
		args args
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handleStreamCache(tt.args.bouncer)
		})
	}
}

func Test_crowdsecQuery(t *testing.T) {
	type args struct {
		bouncer   *Bouncer
		stringURL string
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
			got, err := crowdsecQuery(tt.args.bouncer, tt.args.stringURL)
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

func Test_getTLSConfigCrowdsec(t *testing.T) {
	type args struct {
		config *configuration.Config
	}
	tests := []struct {
		name    string
		args    args
		want    *tls.Config
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := getTLSConfigCrowdsec(tt.args.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("getTLSConfigCrowdsec() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("getTLSConfigCrowdsec() = %v, want %v", got, tt.want)
			}
		})
	}
}
