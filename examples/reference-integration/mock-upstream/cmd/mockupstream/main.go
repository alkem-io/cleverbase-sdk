// Command mockupstream serves a credential-free stand-in for Cleverbase's CSC/OIDC + TSA surface,
// driven by the SDK's shared upstream fixtures. It exists only to make the reference integration
// runnable in CI without Cleverbase credentials.
package main

import (
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/alkem-io/cleverbase-sdk/examples/reference-integration/mock-upstream/mock"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	dir := os.Getenv("REFMOCK_FIXTURES_DIR")
	if dir == "" {
		dir = "/fixtures"
	}
	listen := os.Getenv("REFMOCK_LISTEN")
	if listen == "" {
		listen = ":9000"
	}

	srv, err := mock.New(dir)
	if err != nil {
		logger.Error("mock init", "err", err.Error())
		os.Exit(1)
	}
	logger.Info("mock upstream listening", "addr", listen, "fixtures", dir)
	httpSrv := &http.Server{Addr: listen, Handler: srv.Handler(), ReadHeaderTimeout: 10 * time.Second}
	if err := httpSrv.ListenAndServe(); err != nil {
		logger.Error("serve", "err", err.Error())
		os.Exit(1)
	}
}
