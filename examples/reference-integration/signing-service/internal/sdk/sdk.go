// Package sdk adapts the cgo Go binding to the flow.SDK interface (so the flow package stays
// cgo-free and unit-testable). It re-implements no protocol/crypto — all of that lives in the Rust
// core (Constitution III).
package sdk

import (
	"crypto/rand"
	"time"

	"github.com/fxamacker/cbor/v2"

	bindings "github.com/alkem-io/cleverbase-sdk/bindings/go"
	"github.com/alkem-io/cleverbase-sdk/examples/reference-integration/signing-service/internal/config"
	"github.com/alkem-io/cleverbase-sdk/examples/reference-integration/signing-service/internal/flow"
)

// Adapter wraps the binding with a fixed trust-service config.
type Adapter struct {
	cfg bindings.Config
}

// New builds an adapter from the run profile.
func New(p *config.Profile) *Adapter {
	return &Adapter{cfg: bindings.Config{
		Environment:  p.Environment,
		CscAPI:       p.CscAPI,
		ClientID:     p.ClientID,
		ClientSecret: p.ClientSecret,
		RedirectURI:  p.RedirectURI,
		TsaURL:       p.TsaURL,
		TsaAuth:      p.TsaAuth,
		TsaPolicy:    p.TsaPolicy,
	}}
}

func now() int64 { return time.Now().Unix() }

func entropy() []byte {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return b
}

func toResult(s *bindings.Session) flow.Result {
	return flow.Result{Handle: []byte(s.Handle), Step: s.Step}
}

// Begin starts a signing session.
func (a *Adapter) Begin(document []byte, conformance string, opts *flow.Options) (flow.Result, error) {
	var bopts *bindings.RequestOptions
	if opts != nil && opts.ExpectedSignerValue != "" {
		bopts = &bindings.RequestOptions{ExpectedSigner: &bindings.ExpectedSigner{
			MatchOn: opts.ExpectedSignerMatchOn,
			Value:   opts.ExpectedSignerValue,
		}}
	}
	s, err := bindings.BeginSigning(document, a.cfg, conformance, bopts, now(), entropy())
	if err != nil {
		return flow.Result{}, err
	}
	return toResult(s), nil
}

// ResumeRedirect advances after a redirect return with code+state.
func (*Adapter) ResumeRedirect(handle []byte, code, state string) (flow.Result, error) {
	s, err := bindings.ResumeRedirect(cbor.RawMessage(handle), code, state, now(), entropy())
	if err != nil {
		return flow.Result{}, err
	}
	return toResult(s), nil
}

// ResumeRedirectError advances after a redirect return carrying an OAuth error.
func (*Adapter) ResumeRedirectError(handle []byte, oauthError, state string) (flow.Result, error) {
	s, err := bindings.ResumeRedirectError(cbor.RawMessage(handle), oauthError, state, now(), entropy())
	if err != nil {
		return flow.Result{}, err
	}
	return toResult(s), nil
}

// ResumeHTTP advances after performing an HTTP effect.
func (*Adapter) ResumeHTTP(handle []byte, status int, body []byte) (flow.Result, error) {
	s, err := bindings.ResumeHTTP(cbor.RawMessage(handle), status, body, now(), entropy())
	if err != nil {
		return flow.Result{}, err
	}
	return toResult(s), nil
}
