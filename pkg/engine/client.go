package engine

import (
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"time"
)

// NewOptimizedClient creates an HTTP client tuned for high-concurrency load testing.
func NewOptimizedClient(timeout time.Duration) *http.Client {
	transport := &http.Transport{
		ForceAttemptHTTP2: false,
		MaxIdleConns:        1000,
		MaxIdleConnsPerHost: 500,
		MaxConnsPerHost:     0,
		IdleConnTimeout:     90 * time.Second,
		DialContext: (&net.Dialer{
			Timeout:   5 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
		ResponseHeaderTimeout: time.Second * 10,
		DisableCompression:    true,
	}
	return &http.Client{
		Transport: transport,
		Timeout:   timeout,
	}
}

// DrainBody reads and discards the response body to allow connection reuse.
func DrainBody(resp *http.Response) {
	if resp != nil && resp.Body != nil {
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
}
