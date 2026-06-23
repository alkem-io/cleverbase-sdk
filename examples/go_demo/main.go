// Demo: start a signing flow with the Cleverbase Go binding.
//
// Build the C ABI first:  cargo build -p cleverbase-ffi
// Run:  DYLD_LIBRARY_PATH=$PWD/target/debug go run ./examples/go_demo   (LD_LIBRARY_PATH on Linux)
package main

import (
	"crypto/rand"
	"fmt"
	"time"

	cleverbase "github.com/alkem-io/cleverbase-sdk/bindings/go"
)

func main() {
	entropy := make([]byte, 16)
	_, _ = rand.Read(entropy)

	cfg := cleverbase.Config{
		Environment:  "acceptance",
		CscAPI:       "v1_rsa",
		ClientID:     "your-client-id",
		ClientSecret: "your-client-secret",
		RedirectURI:  "https://your-app.example/callback",
	}
	// Optional: bind to an expected signer (FR-014) and/or a visible appearance (FR-016); pass nil
	// for neither.
	opts := &cleverbase.RequestOptions{
		ExpectedSigner: &cleverbase.ExpectedSigner{MatchOn: "certificate_serial_number", Value: "PNONL-123"},
		SignatureMeta:  &cleverbase.SignatureMeta{Reason: "Approval", Location: "NL"},
	}
	sess, err := cleverbase.BeginSigning([]byte("%PDF-1.7\n... your document ..."), cfg, "B-B", opts, time.Now().Unix(), entropy)
	if err != nil {
		panic(err)
	}
	fmt.Printf("First step: %v\n", sess.Step["kind"])
	if sess.Step["kind"] == "redirect" {
		fmt.Printf("Send the signer to:\n  %v\n", sess.Step["url"])
		fmt.Println("Persist sess.Handle server-side; resume with the returned code+state.")
	}
}
