// Command refweb is the reference frontend's tiny BFF: it serves the no-crypto static bundle and
// reverse-proxies /api/* to the signing service, injecting the API key server-side so the browser
// never holds a secret. Health is GET / (a static page); there is no /healthz.
package main

import (
	"log/slog"
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
	target := env("REFWEB_API_TARGET", "http://signing-service:8080")
	apiKey := os.Getenv("REFWEB_API_KEY") // injected into proxied requests; never sent to the browser
	staticDir := env("REFWEB_STATIC_DIR", "/web")

	u, err := url.Parse(target)
	if err != nil {
		logger.Error("bad REFWEB_API_TARGET", "err", err.Error())
		os.Exit(1)
	}

	proxy := httputil.NewSingleHostReverseProxy(u)
	base := proxy.Director
	proxy.Director = func(r *http.Request) {
		base(r)
		// /api/v1/sign/start -> /v1/sign/start on the signing service.
		r.URL.Path = strings.TrimPrefix(r.URL.Path, "/api")
		r.Host = u.Host
		if apiKey != "" {
			r.Header.Set("Authorization", "Bearer "+apiKey)
		}
	}

	mux := http.NewServeMux()
	mux.Handle("/api/", proxy)
	mux.Handle("/", http.FileServer(http.Dir(staticDir)))

	logger.Info("reference web listening", "addr", listen, "api_target", target, "static", staticDir)
	srv := &http.Server{Addr: listen, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	if err := srv.ListenAndServe(); err != nil {
		logger.Error("serve", "err", err.Error())
		os.Exit(1)
	}
}
