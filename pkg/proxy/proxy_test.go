package proxy

import (
	"net/http"
	"net/url"
	"testing"
)

func TestCheckTargetOnlyAllowsSafeHTTPURLs(t *testing.T) {
	t.Parallel()
	valid, _ := url.Parse("https://upstream.example/path")
	if err := CheckTarget(valid); err != nil {
		t.Fatalf("valid target rejected: %v", err)
	}
	for _, raw := range []string{"file:///etc/passwd", "https://user:pass@example.com", "/relative"} {
		target, _ := url.Parse(raw)
		if err := CheckTarget(target); err == nil {
			t.Errorf("unsafe target accepted: %s", raw)
		}
	}
}

func TestCacheHeadersDoNotExposePrivateResponses(t *testing.T) {
	t.Parallel()
	request := &http.Request{URL: &url.URL{Path: "/account.js"}, Header: make(http.Header)}
	response := &http.Response{Request: request, Header: make(http.Header)}
	response.Header.Set("Set-Cookie", "session=secret")
	setCacheHeaders(response)
	if got := response.Header.Get("Cache-Control"); got != noCache {
		t.Fatalf("cookie response cache policy = %q", got)
	}

	response = &http.Response{Request: request, Header: make(http.Header)}
	response.Header.Set("Cache-Control", "private, max-age=60")
	setCacheHeaders(response)
	if got := response.Header.Get("Cache-Control"); got != "private, max-age=60" {
		t.Fatalf("upstream cache policy overwritten: %q", got)
	}
}
