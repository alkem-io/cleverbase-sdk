// Command refweb is the reference frontend's tiny BFF: it serves the no-crypto static bundle and
// reverse-proxies /api/* to the signing service, injecting the API key server-side so the browser
// never holds a secret. Health is GET / (a static page); there is no /healthz.
package main

import (
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"time"
)

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	listen := env("REFWEB_LISTEN", ":8080")
	// The default targets the signing service over the in-cluster/compose network; that hop is plain
	// HTTP by design (TLS terminates at the ingress), so the http:// scheme is correct here.
	target := env("REFWEB_API_TARGET", "http://signing-service:8080") //nolint:revive // unsecure-url-scheme: internal cluster target, TLS at ingress
	apiKey := os.Getenv("REFWEB_API_KEY")                             // injected into proxied requests; never sent to the browser
	staticDir := env("REFWEB_STATIC_DIR", "/web")

	// url.Parse alone only rejects syntax errors, so "http://" (no host) or "signing-service:8080"
	// (parsed as scheme "signing-service", opaque "8080", no host) would pass startup and then break
	// every proxied request. Require an absolute URL with an http/https scheme AND a host so a
	// misconfigured target fails fast at startup rather than at the first proxy hop.
	u, err := url.Parse(target)
	if err != nil {
		logger.Error("bad REFWEB_API_TARGET", "err", err.Error())
		os.Exit(1)
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		logger.Error("bad REFWEB_API_TARGET: must be an absolute http(s) URL with a host", "target", target)
		os.Exit(1)
	}

	proxy := httputil.NewSingleHostReverseProxy(u)
	base := proxy.Director
	proxy.Director = func(r *http.Request) {
		base(r)
		// /api/v1/sign/start -> /v1/sign/start on the signing service.
		r.URL.Path = strings.TrimPrefix(r.URL.Path, "/api")
		r.Host = u.Host
		// Strip any caller-supplied credentials so the browser can never inject upstream auth: the
		// server-injected API key is the ONLY auth that reaches the signing service. Done
		// unconditionally (even when apiKey is empty) so an empty key cannot let a client header pass.
		r.Header.Del("Authorization")
		r.Header.Del("Cookie")
		if apiKey != "" {
			r.Header.Set("Authorization", "Bearer "+apiKey)
		}
	}
	// Bound the upstream hop so a wedged signing service cannot pin proxy handler goroutines forever.
	proxy.Transport = &http.Transport{
		DialContext:           (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
		ResponseHeaderTimeout: 150 * time.Second, // accommodates the multi-call signing round-trip
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
	}

	mux := http.NewServeMux()
	mux.Handle("/api/", proxy)
	mux.Handle("/", http.FileServer(http.Dir(staticDir)))

	// Log the redacted URL (u.Redacted()) rather than the raw target string so any userinfo
	// credentials (user:pass@host) configured in REFWEB_API_TARGET cannot leak into the logs.
	logger.Info("reference web listening", "addr", listen, "api_target", u.Redacted(), "static", staticDir)
	// WriteTimeout is generous because /api proxies the signing round-trip (multiple upstream calls);
	// ReadTimeout/IdleTimeout bound slow request bodies and idle keep-alives.
	srv := &http.Server{
		Addr:              listen,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      150 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	if err := srv.ListenAndServe(); err != nil {
		logger.Error("serve", "err", err.Error())
		os.Exit(1)
	}
}
