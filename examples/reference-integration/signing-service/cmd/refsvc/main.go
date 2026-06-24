// Command refsvc is the reference signing service: it embeds the Cleverbase SDK (via the Go binding)
// and serves the REST API that the no-crypto web frontend drives. See specs/002-reference-integration.
package main

import (
	"context"
	_ "embed"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/alkem-io/cleverbase-sdk/examples/reference-integration/signing-service/internal/config"
	"github.com/alkem-io/cleverbase-sdk/examples/reference-integration/signing-service/internal/flow"
	"github.com/alkem-io/cleverbase-sdk/examples/reference-integration/signing-service/internal/httpapi"
	"github.com/alkem-io/cleverbase-sdk/examples/reference-integration/signing-service/internal/sdk"
	"github.com/alkem-io/cleverbase-sdk/examples/reference-integration/signing-service/internal/session"
	"github.com/alkem-io/cleverbase-sdk/examples/reference-integration/signing-service/internal/upstream"
)

//go:embed sample.pdf
var samplePDF []byte

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	p, err := config.Load()
	if err != nil {
		logger.Error("config", "err", err.Error())
		os.Exit(1)
	}

	store := session.NewMemory()
	var internalRewrite, publicRewrite string
	if p.Mode == config.ModeFixtures {
		internalRewrite = p.UpstreamBaseURL     // server-side effects → internal mock host
		publicRewrite = p.PublicUpstreamBaseURL // browser redirects → reachable mock host
	}
	engine := &flow.Engine{
		SDK:             sdk.New(p),
		Up:              upstream.New(internalRewrite),
		Store:           store,
		Log:             logger,
		TTL:             p.SessionTTL,
		RedirectRewrite: upstream.New(publicRewrite).Rewrite,
	}
	svc := &httpapi.Service{Engine: engine, Store: store, Profile: p, Sample: samplePDF, Log: logger}

	srv := &http.Server{Addr: p.Listen, Handler: svc.Handler(), ReadHeaderTimeout: 10 * time.Second}

	go func() {
		logger.Info("listening", "addr", p.Listen, "mode", string(p.Mode), "auth", p.AuthEnabled)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("serve", "err", err.Error())
			os.Exit(1)
		}
	}()

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	<-sigs

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = srv.Shutdown(ctx)
	logger.Info("stopped")
}
