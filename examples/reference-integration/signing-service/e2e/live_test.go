package e2e

import (
	"io"
	"log/slog"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/alkem-io/cleverbase-sdk/examples/reference-integration/signing-service/internal/config"
	"github.com/alkem-io/cleverbase-sdk/examples/reference-integration/signing-service/internal/flow"
	"github.com/alkem-io/cleverbase-sdk/examples/reference-integration/signing-service/internal/httpapi"
	"github.com/alkem-io/cleverbase-sdk/examples/reference-integration/signing-service/internal/sdk"
	"github.com/alkem-io/cleverbase-sdk/examples/reference-integration/signing-service/internal/session"
	"github.com/alkem-io/cleverbase-sdk/examples/reference-integration/signing-service/internal/upstream"
)

// TestLiveSmoke is skipped unless real Cleverbase acceptance credentials are present. With them, it
// confirms the SAME service wiring drives a live signer: a start request produces a genuine
// Cleverbase authorization redirect (the journey can only be completed by a human signer, so the
// smoke stops at the first redirect). Artifacts are otherwise byte-identical to fixtures mode
// (SC-003): only configuration differs.
func TestLiveSmoke(t *testing.T) {
	clientID := os.Getenv("REFSVC_CLIENT_ID")
	clientSecret := os.Getenv("REFSVC_CLIENT_SECRET")
	redirectURI := os.Getenv("REFSVC_REDIRECT_URI")
	if clientID == "" || clientSecret == "" || redirectURI == "" {
		t.Skip("live smoke requires REFSVC_CLIENT_ID, REFSVC_CLIENT_SECRET, REFSVC_REDIRECT_URI")
	}

	env := os.Getenv("REFSVC_ENV")
	if env == "" {
		env = "acceptance"
	}
	csc := os.Getenv("REFSVC_CSC_API")
	if csc == "" {
		csc = "v1_rsa"
	}
	p := &config.Profile{
		Mode: config.ModeLive, Environment: env, CscAPI: csc,
		ClientID: clientID, ClientSecret: clientSecret, RedirectURI: redirectURI,
		APIKey: apiKey, AuthEnabled: true, DefaultConformance: "B-B", SessionTTL: time.Minute,
	}
	store := session.NewMemory()
	eng := &flow.Engine{
		SDK: sdk.New(p), Up: upstream.New(""), Store: store, // live: no host rewrite
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)), TTL: p.SessionTTL,
	}
	service := &httpapi.Service{Engine: eng, Store: store, Profile: p, Sample: samplePDF(t)}
	svc := httptest.NewServer(service.Handler())
	defer svc.Close()

	start := postJSON(t, svc.URL+"/v1/sign/start", `{"conformanceLevel":"B-B"}`)
	redirect, _ := start["redirectUrl"].(string)
	if !strings.Contains(redirect, "cleverbase.com") || !strings.Contains(redirect, "/oauth2/authorize") {
		t.Fatalf("live start should return a Cleverbase authorization redirect, got %q", redirect)
	}
}
