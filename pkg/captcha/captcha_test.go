package captcha

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestClient_HasResponse(t *testing.T) {
	client := &Client{infoProvider: &infoProvider{response: "h-captcha-response"}}
	form := "application/x-www-form-urlencoded"

	tests := []struct {
		name        string
		method      string
		contentType string
		body        string
		length      int64
		want        bool
	}{
		{name: "captcha form", method: http.MethodPost, contentType: form, body: "h-captcha-response=token", want: true},
		{name: "other form", method: http.MethodPost, contentType: form, body: "name=value"},
		{name: "get", method: http.MethodGet, contentType: form, body: "h-captcha-response=token"},
		{name: "json", method: http.MethodPost, contentType: "application/json", body: `{"h-captcha-response":"token"}`},
		{name: "unknown length", method: http.MethodPost, contentType: form, body: "h-captcha-response=token", length: -1},
		{name: "too large", method: http.MethodPost, contentType: form, body: "h-captcha-response=token&" + strings.Repeat("a", responseFormLimit)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, "http://example.com/page", strings.NewReader(tt.body))
			req.Header.Set("Content-Type", tt.contentType)
			if tt.length != 0 {
				req.ContentLength = tt.length
			}
			if got := client.HasResponse(req); got != tt.want {
				t.Errorf("HasResponse() = %v, want %v", got, tt.want)
			}
			body, _ := io.ReadAll(req.Body)
			if string(body) != tt.body {
				t.Errorf("body after HasResponse() = %q, want %q", body, tt.body)
			}
		})
	}
}
