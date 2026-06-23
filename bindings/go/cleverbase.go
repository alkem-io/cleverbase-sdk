// Package cleverbase is the Go binding for the Cleverbase SDK.
//
// It wraps the Rust core's stable C ABI (CBOR request in / result out) and exposes typed Go
// functions. All protocol/crypto logic lives in the Rust core (Constitution Principle III); this
// package only marshals CBOR and calls across the FFI boundary. The opaque session handle is kept
// as raw CBOR and passed back verbatim on resume.
package cleverbase

/*
#cgo LDFLAGS: -L${SRCDIR}/../../target/debug -lcleverbase_ffi -Wl,-rpath,${SRCDIR}/../../target/debug
#include <stdint.h>
#include <stdlib.h>
int cleverbase_process(const uint8_t* in, size_t in_len, uint8_t** out, size_t* out_len);
void cleverbase_free(uint8_t* out, size_t out_len);
*/
import "C"

import (
	"errors"
	"reflect"
	"unsafe"

	"github.com/fxamacker/cbor/v2"
)

const schemaVersion = 1

// Decode nested CBOR maps as map[string]interface{} (not the default map[interface{}]interface{}),
// so callers can index Step fields with string keys.
var decMode cbor.DecMode

func init() {
	var err error
	decMode, err = cbor.DecOptions{
		DefaultMapType: reflect.TypeOf(map[string]interface{}(nil)),
	}.DecMode()
	if err != nil {
		panic(err)
	}
}

// Config identifies the Cleverbase environment and OAuth client.
type Config struct {
	Environment  string // "acceptance" | "production"
	CscAPI       string // "v1_rsa" | "v2_ecdsa"
	ClientID     string
	ClientSecret string
	RedirectURI  string
	TsaURL       string // optional; "" means none (required for B-T)
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
type Step = map[string]interface{}

// Session is the opaque, serializable handle plus the latest Step.
type Session struct {
	Handle cbor.RawMessage
	Step   Step
}

type okResult struct {
	Handle cbor.RawMessage `cbor:"handle"`
	Step   Step            `cbor:"step"`
}

type wireResponse struct {
	SchemaVersion int `cbor:"schema_version"`
	Result        struct {
		Ok  *okResult `cbor:"ok"`
		Err *struct {
			Message string `cbor:"message"`
		} `cbor:"err"`
	} `cbor:"result"`
}

// process calls the Rust core with a CBOR request envelope and returns the CBOR response.
func process(input []byte) ([]byte, error) {
	if len(input) == 0 {
		return nil, errors.New("empty input")
	}
	var outPtr *C.uint8_t
	var outLen C.size_t
	rc := C.cleverbase_process((*C.uint8_t)(unsafe.Pointer(&input[0])), C.size_t(len(input)), &outPtr, &outLen)
	if rc != 0 {
		return nil, errors.New("cleverbase_process returned a non-zero status")
	}
	defer C.cleverbase_free(outPtr, outLen)
	return C.GoBytes(unsafe.Pointer(outPtr), C.int(outLen)), nil
}

func dispatch(op map[string]interface{}) (*Session, error) {
	req := map[string]interface{}{"schema_version": schemaVersion, "op": op}
	in, err := cbor.Marshal(req)
	if err != nil {
		return nil, err
	}
	out, err := process(in)
	if err != nil {
		return nil, err
	}
	var resp wireResponse
	if err := decMode.Unmarshal(out, &resp); err != nil {
		return nil, err
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
	config := map[string]interface{}{
		"environment":   cfg.Environment,
		"csc_api":       cfg.CscAPI,
		"client_id":     cfg.ClientID,
		"client_secret": cfg.ClientSecret,
		"redirect_uri":  cfg.RedirectURI,
	}
	if cfg.TsaURL != "" {
		config["tsa"] = map[string]interface{}{"url": cfg.TsaURL}
	}
	request := map[string]interface{}{"document": document, "conformance_level": conformance}
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
	return dispatch(map[string]interface{}{
		"op":      "begin",
		"request": request,
		"config":  config,
		"ctx":     map[string]interface{}{"now_unix": nowUnix, "entropy": entropy},
	})
}

// ResumeRedirect advances the flow with the OAuth code+state from a redirect return.
func ResumeRedirect(handle cbor.RawMessage, code, state string, nowUnix int64, entropy []byte) (*Session, error) {
	return dispatch(map[string]interface{}{
		"op":     "resume",
		"handle": handle,
		"input":  map[string]interface{}{"kind": "redirect_return", "code": code, "state": state},
		"ctx":    map[string]interface{}{"now_unix": nowUnix, "entropy": entropy},
	})
}

// ResumeRedirectError advances the flow with an OAuth error returned to the redirect URI instead
// of a code (e.g. "access_denied" when the signer declines), yielding a terminal Declined or
// AuthorizationExpired outcome.
func ResumeRedirectError(handle cbor.RawMessage, oauthError, state string, nowUnix int64, entropy []byte) (*Session, error) {
	return dispatch(map[string]interface{}{
		"op":     "resume",
		"handle": handle,
		"input":  map[string]interface{}{"kind": "redirect_error", "error": oauthError, "state": state},
		"ctx":    map[string]interface{}{"now_unix": nowUnix, "entropy": entropy},
	})
}

// ResumeHTTP advances the flow with the result of a performed HTTP effect.
func ResumeHTTP(handle cbor.RawMessage, status int, body []byte, nowUnix int64, entropy []byte) (*Session, error) {
	return dispatch(map[string]interface{}{
		"op":     "resume",
		"handle": handle,
		"input":  map[string]interface{}{"kind": "http_result", "status": status, "headers": []interface{}{}, "body": body},
		"ctx":    map[string]interface{}{"now_unix": nowUnix, "entropy": entropy},
	})
}
