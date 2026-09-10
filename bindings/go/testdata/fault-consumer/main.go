// Command fault-consumer exercises public Go binding APIs against the external ABI fault fixture.
package main

import (
	"fmt"
	"os"
	"strings"

	cleverbase "github.com/alkem-io/cleverbase-sdk/bindings/go"
)

func main() {
	mode := os.Getenv("CLEVERBASE_FFI_FAULT")
	want := map[string]string{
		"nonzero":        "returned a non-zero status: 17",
		"oversized":      "output too large: 2147483648 bytes",
		"invalid_cbor":   "unexpected \"break\" code",
		"wrong_schema":   "unexpected schema_version 2 (expected 1)",
		"missing_config": "malformed response: missing config-validation result",
		"missing_ok":     "malformed response: neither ok nor err",
		"missing_verify": "malformed response: missing verification result",
	}[mode]
	if want == "" {
		fmt.Fprintf(os.Stderr, "unknown fault mode %q\n", mode)
		os.Exit(2)
	}

	var err error
	switch mode {
	case "missing_ok":
		_, err = cleverbase.BeginSigning(
			[]byte("%PDF-1.7\nminimal"), validConfig(), "B-B", nil, 1_700_000_000, make([]byte, 16),
		)
	case "missing_verify":
		_, err = cleverbase.VerifyPDF([]byte("not a pdf"))
	default:
		err = validConfig().Validate()
	}
	if err == nil || !strings.Contains(err.Error(), want) {
		fmt.Fprintf(os.Stderr, "fault %q: got error %v, want substring %q\n", mode, err, want)
		os.Exit(1)
	}
}

func validConfig() cleverbase.Config {
	return cleverbase.Config{
		Environment:  "acceptance",
		CscAPI:       "v1_rsa",
		ClientID:     "client",
		ClientSecret: "secret",
		RedirectURI:  "https://app.example/callback",
	}
}
