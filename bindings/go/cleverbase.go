// Package cleverbase is the Go binding for the Cleverbase SDK.
//
// It wraps the Rust core's stable C ABI (CBOR request in / result out) and exposes typed Go
// functions. All protocol/crypto logic lives in the Rust core (Constitution Principle III); this
// package only marshals CBOR and calls across the FFI boundary. The opaque session handle is kept
// as raw CBOR and passed back verbatim on resume.
package cleverbase

/*
// The default LDFLAGS point at this repo's debug build of cleverbase-ffi so the binding works
// in-tree for development and CI. Consumers building against a packaged/release library override
// these via the CGO_LDFLAGS environment variable, e.g.
//   CGO_LDFLAGS="-L/opt/cleverbase/lib -lcleverbase_ffi -Wl,-rpath,/opt/cleverbase/lib"
#cgo LDFLAGS: -L${SRCDIR}/../../target/debug -lcleverbase_ffi -Wl,-rpath,${SRCDIR}/../../target/debug
#include <stdint.h>
#include <stdlib.h>
int cleverbase_process(const uint8_t* in, size_t in_len, uint8_t** out, size_t* out_len);
int cleverbase_attestation_verify(const uint8_t* in, size_t in_len, uint8_t** out, size_t* out_len);
int cleverbase_attestation_verify_vp_token(const uint8_t* in, size_t in_len, uint8_t** out, size_t* out_len);
int cleverbase_attestation_issuance(const uint8_t* in, size_t in_len, uint8_t** out, size_t* out_len);
void cleverbase_free(uint8_t* out, size_t out_len);
*/
import "C"

import (
	"errors"
	"fmt"
	"math"
	"reflect"
	"sync"
	"unsafe"

	"github.com/fxamacker/cbor/v2"
)

const schemaVersion = 1

// Wire-envelope keys shared across the op requests, factored out so the request shape has a single
// authoritative spelling (Constitution Principle III).
const (
	keyOp            = "op"
	keyHandle        = "handle"
	keyInput         = "input"
	keyCtx           = "ctx"
	keyKind          = "kind"
	keyEntropy       = "entropy"
	keyNowUnix       = "now_unix"
	opResume         = "resume"
	keySchemaVersion = "schema_version"
)

// decMode decodes nested CBOR maps as map[string]any (not the default map[any]any), so callers can
// index Step fields with string keys. It is built once on first use; the options are static and
// cannot fail at runtime, but the error is surfaced as a panic rather than ignored.
var decMode = sync.OnceValue(func() cbor.DecMode {
	m, err := cbor.DecOptions{
		DefaultMapType: reflect.TypeOf(map[string]any(nil)),
	}.DecMode()
	if err != nil {
		panic(err)
	}
	return m
})

// Config identifies the Cleverbase environment and OAuth client.
type Config struct {
	Environment  string // "acceptance" | "production"
	CscAPI       string // "v1_rsa" | "v2_ecdsa"
	ClientID     string
	ClientSecret string
	RedirectURI  string
	TsaURL       string // optional; "" means none (required for B-T)
	TsaAuth      string // optional TSA request Authorization header value
	TsaPolicy    string // optional TSA policy OID
}

// ExpectedSigner binds the request to a signer identity (FR-014). MatchOn is
// "certificate_serial_number" (default, used when empty) or "cleverbase_subject".
type ExpectedSigner struct {
	// omitempty so an unset MatchOn is omitted (not sent as ""), letting the core apply its default.
	MatchOn string `cbor:"match_on,omitempty"`
	Value   string `cbor:"value"`
}

// Rect is a signature-appearance rectangle in PDF user-space points.
type Rect struct {
	X float64 `cbor:"x"`
	Y float64 `cbor:"y"`
	W float64 `cbor:"w"`
	H float64 `cbor:"h"`
}

// AppearanceShow selects which lines a visible appearance renders.
type AppearanceShow struct {
	SignerName  bool `cbor:"signer_name"`
	Reason      bool `cbor:"reason"`
	Location    bool `cbor:"location"`
	SigningTime bool `cbor:"signing_time"`
}

// Appearance is an optional visible signature block (FR-016). Page is 1-based.
type Appearance struct {
	Page uint32         `cbor:"page"`
	Rect Rect           `cbor:"rect"`
	Show AppearanceShow `cbor:"show"`
}

// SignatureMeta carries optional PAdES reason/location.
type SignatureMeta struct {
	Reason   string `cbor:"reason,omitempty"`
	Location string `cbor:"location,omitempty"`
}

// RequestOptions holds the optional parts of a signing request; pass nil for none.
type RequestOptions struct {
	ExpectedSigner *ExpectedSigner
	Appearance     *Appearance
	SignatureMeta  *SignatureMeta
}

// Step is the next action the host must perform (a decoded CBOR map: "kind" plus fields).
type Step = map[string]any

// Session is the opaque, serializable handle plus the latest Step.
type Session struct {
	Handle cbor.RawMessage
	Step   Step
}

type okResult struct {
	Handle cbor.RawMessage `cbor:"handle"`
	Step   Step            `cbor:"step"`
}

type wireError struct {
	Message string `cbor:"message"`
}

type wireResult struct {
	Ok  *okResult  `cbor:"ok"`
	Err *wireError `cbor:"err"`
}

type wireResponse struct {
	SchemaVersion int        `cbor:"schema_version"`
	Result        wireResult `cbor:"result"`
}

// callAbi invokes one of the Cleverbase C-ABI CBOR-in / CBOR-out entry points, applying the shared
// out-ptr/out-len + cleverbase_free discipline, and returns the response bytes. The specific entry
// point is supplied as a closure so all three (signing, attestation verify, attestation issuance)
// share one marshaling + free path (Constitution Principle III). A non-nil error means the FFI call
// itself failed (null arg, contained panic, or an oversized buffer) — protocol/verdict outcomes ride
// inside the returned CBOR.
func callAbi(name string, input []byte, call func(in *C.uint8_t, inLen C.size_t, out **C.uint8_t, outLen *C.size_t) C.int) ([]byte, error) {
	if len(input) == 0 {
		return nil, errors.New("empty input")
	}
	var outPtr *C.uint8_t
	var outLen C.size_t
	rc := call((*C.uint8_t)(unsafe.Pointer(&input[0])), C.size_t(len(input)), &outPtr, &outLen)
	if rc != 0 {
		return nil, fmt.Errorf("%s returned a non-zero status: %d", name, int(rc))
	}
	defer C.cleverbase_free(outPtr, outLen)
	// C.GoBytes takes an int length; guard the size_t→int narrowing against overflow.
	if uint64(outLen) > uint64(math.MaxInt32) {
		return nil, fmt.Errorf("%s output too large: %d bytes", name, uint64(outLen))
	}
	return C.GoBytes(unsafe.Pointer(outPtr), C.int(outLen)), nil
}

// process calls the signing C-ABI entry point with a CBOR request envelope and returns the response.
func process(input []byte) ([]byte, error) {
	return callAbi("cleverbase_process", input, func(in *C.uint8_t, inLen C.size_t, out **C.uint8_t, outLen *C.size_t) C.int {
		return C.cleverbase_process(in, inLen, out, outLen)
	})
}

// AttestationVerify runs the EUDI attestation verifier over a CBOR VerifyRequest envelope
// (attestation schema version 5) and returns the CBOR VerifyResponse. Unlike the signing surface,
// the attestation surface is CBOR-in / CBOR-out: the caller builds the VerifyRequest and decodes the
// VerifyResponse per the documented wire schema (see
// specs/004-attestation-and-verification/standards-conformance.md). The VALID/INVALID verdict (and any
// decode error) rides inside the VerifyResponse `outcome`; a non-nil error here means the FFI call
// itself failed (null/oversized/contained-panic), never a mere INVALID verdict.
func AttestationVerify(request []byte) ([]byte, error) {
	return callAbi("cleverbase_attestation_verify", request, func(in *C.uint8_t, inLen C.size_t, out **C.uint8_t, outLen *C.size_t) C.int {
		return C.cleverbase_attestation_verify(in, inLen, out, outLen)
	})
}

// AttestationVerifyVpToken runs the EUDI attestation SET-LEVEL OpenID4VP verifier over a CBOR
// WireVpTokenRequest envelope (attestation schema version 5) and returns the CBOR WireVpTokenResponse.
// Unlike AttestationVerify (a single presentation), this carries the whole multi-credential vp_token
// (`{credential_id: [presentations]}`) so the core folds the OpenID4VP set-level DCQL semantics
// (`credential_sets` required option-sets + `multiple` cardinality) AND authenticates supplied signed
// Token Status List tokens in-core across the set. Like AttestationVerify it is CBOR-in / CBOR-out: the
// overall `satisfied` verdict + per-credential results (and any decode error) ride inside the response
// `outcome`; a non-nil error here means the FFI call itself failed (null/oversized/contained-panic),
// never a mere unsatisfied verdict.
//
// The set-level surface does NOT run the opt-in eIDAS qualified-status gate: a request with
// policy.qualified_gate = true is rejected with an `err` outcome (verify each presentation via
// AttestationVerify if the qualified gate is required).
func AttestationVerifyVpToken(request []byte) ([]byte, error) {
	return callAbi("cleverbase_attestation_verify_vp_token", request, func(in *C.uint8_t, inLen C.size_t, out **C.uint8_t, outLen *C.size_t) C.int {
		return C.cleverbase_attestation_verify_vp_token(in, inLen, out, outLen)
	})
}

// AttestationIssuance drives the EUDI attestation issuance / presentation sans-IO state machine over
// a CBOR IssuanceRequest envelope (issuance schema version 1) and returns the CBOR IssuanceResponse.
// Like AttestationVerify it is CBOR-in / CBOR-out (see the wire schema). The holder's private key
// never crosses this boundary: a `sign` step surfaces a signing input the host signs out-of-process
// and feeds back via a follow-up op (finish_present / resume_obtain).
func AttestationIssuance(request []byte) ([]byte, error) {
	return callAbi("cleverbase_attestation_issuance", request, func(in *C.uint8_t, inLen C.size_t, out **C.uint8_t, outLen *C.size_t) C.int {
		return C.cleverbase_attestation_issuance(in, inLen, out, outLen)
	})
}

func dispatch(op map[string]any) (*Session, error) {
	req := map[string]any{keySchemaVersion: schemaVersion, keyOp: op}
	in, err := cbor.Marshal(req)
	if err != nil {
		return nil, err
	}
	out, err := process(in)
	if err != nil {
		return nil, err
	}
	var resp wireResponse
	if err := decMode().Unmarshal(out, &resp); err != nil {
		return nil, err
	}
	// Refuse a response from an unexpected schema version rather than silently mis-decoding it
	// after a wire-format bump (the binding and the core must agree on the envelope version).
	if resp.SchemaVersion != schemaVersion {
		return nil, fmt.Errorf("unexpected schema_version %d (expected %d)", resp.SchemaVersion, schemaVersion)
	}
	if resp.Result.Err != nil {
		return nil, errors.New(resp.Result.Err.Message)
	}
	if resp.Result.Ok == nil {
		return nil, errors.New("malformed response: neither ok nor err")
	}
	return &Session{Handle: resp.Result.Ok.Handle, Step: resp.Result.Ok.Step}, nil
}

// BeginSigning starts a signing flow and returns the first Step. Pass opts (or nil) for the
// optional expected-signer / appearance / signature-metadata parts of the request.
func BeginSigning(document []byte, cfg Config, conformance string, opts *RequestOptions, nowUnix int64, entropy []byte) (*Session, error) {
	config := map[string]any{
		"environment":   cfg.Environment,
		"csc_api":       cfg.CscAPI,
		"client_id":     cfg.ClientID,
		"client_secret": cfg.ClientSecret,
		"redirect_uri":  cfg.RedirectURI,
	}
	if cfg.TsaURL != "" {
		tsa := map[string]any{"url": cfg.TsaURL}
		if cfg.TsaAuth != "" {
			tsa["auth"] = cfg.TsaAuth
		}
		if cfg.TsaPolicy != "" {
			tsa["policy_oid"] = cfg.TsaPolicy
		}
		config["tsa"] = tsa
	}
	request := map[string]any{"document": document, "conformance_level": conformance}
	if opts != nil {
		if opts.ExpectedSigner != nil {
			request["expected_signer"] = opts.ExpectedSigner
		}
		if opts.Appearance != nil {
			request["appearance"] = opts.Appearance
		}
		if opts.SignatureMeta != nil {
			request["signature_meta"] = opts.SignatureMeta
		}
	}
	return dispatch(map[string]any{
		keyOp:     "begin",
		"request": request,
		"config":  config,
		keyCtx:    map[string]any{keyNowUnix: nowUnix, keyEntropy: entropy},
	})
}

// ResumeRedirect advances the flow with the OAuth code+state from a redirect return.
func ResumeRedirect(handle cbor.RawMessage, code, state string, nowUnix int64, entropy []byte) (*Session, error) {
	return dispatch(map[string]any{
		keyOp:     opResume,
		keyHandle: handle,
		keyInput:  map[string]any{keyKind: "redirect_return", "code": code, "state": state},
		keyCtx:    map[string]any{keyNowUnix: nowUnix, keyEntropy: entropy},
	})
}

// ResumeRedirectError advances the flow with an OAuth error returned to the redirect URI instead
// of a code (e.g. "access_denied" when the signer declines), yielding a terminal Declined or
// AuthorizationExpired outcome.
func ResumeRedirectError(handle cbor.RawMessage, oauthError, state string, nowUnix int64, entropy []byte) (*Session, error) {
	return dispatch(map[string]any{
		keyOp:     opResume,
		keyHandle: handle,
		keyInput:  map[string]any{keyKind: "redirect_error", "error": oauthError, "state": state},
		keyCtx:    map[string]any{keyNowUnix: nowUnix, keyEntropy: entropy},
	})
}

// ResumeHTTP advances the flow with the result of a performed HTTP effect.
func ResumeHTTP(handle cbor.RawMessage, status int, body []byte, nowUnix int64, entropy []byte) (*Session, error) {
	return dispatch(map[string]any{
		keyOp:     opResume,
		keyHandle: handle,
		keyInput:  map[string]any{keyKind: "http_result", "status": status, "headers": []any{}, "body": body},
		keyCtx:    map[string]any{keyNowUnix: nowUnix, keyEntropy: entropy},
	})
}
