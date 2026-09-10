package cleverbase

import (
	"os"
	"testing"
)

const (
	year0000Start = int64(-62_167_219_200)
	year9999End   = int64(253_402_300_799)
)

func TestVerifyPDFReturnsTypedValidVerdict(t *testing.T) {
	document, err := os.ReadFile("../../tests/fixtures/pades-bt/rsa.pdf")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	verification, err := VerifyPDF(document)
	if err != nil {
		t.Fatalf("VerifyPDF: %v", err)
	}
	if !verification.Integrity {
		t.Fatalf("integrity = false, reasons = %#v", verification.Reasons)
	}
	if verification.Profile == nil || *verification.Profile != "B-T" {
		t.Fatalf("profile = %#v, want B-T", verification.Profile)
	}
	if verification.Signer == nil {
		t.Fatal("signer = nil")
	}
	if verification.Signer.Serial != "07FB0DA8384404C33517B852CFE79F04C5006AC1" ||
		verification.Signer.CN != "Jane Doe" {
		t.Fatalf("signer = %#v", verification.Signer)
	}
	if len(verification.Reasons) != 0 {
		t.Fatalf("reasons = %#v, want empty", verification.Reasons)
	}
}

func TestVerifyPDFReturnsTypedInvalidVerdicts(t *testing.T) {
	legacy, err := os.ReadFile(
		"../../tests/fixtures/pades-conformance/cleverbase-acceptance-dev-2026-09-10.pdf",
	)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	for name, test := range map[string]struct {
		document []byte
		reason   string
	}{
		"not PDF":          {document: []byte("not a PDF"), reason: "not_pdf"},
		"legacy ByteRange": {document: legacy, reason: "malformed_byte_range"},
	} {
		t.Run(name, func(t *testing.T) {
			verification, err := VerifyPDF(test.document)
			if err != nil {
				t.Fatalf("VerifyPDF: %v", err)
			}
			if verification.Integrity {
				t.Fatal("integrity = true")
			}
			if verification.Profile != nil {
				t.Fatalf("profile = %#v, want nil", verification.Profile)
			}
			if verification.Signer != nil {
				t.Fatalf("signer = %#v, want nil", verification.Signer)
			}
			if len(verification.Reasons) != 1 || verification.Reasons[0] != test.reason {
				t.Fatalf("reasons = %#v, want [%s]", verification.Reasons, test.reason)
			}
		})
	}
}

func TestBeginSigningHostContextBoundaries(t *testing.T) {
	for _, nowUnix := range []int64{year0000Start, year9999End} {
		if _, err := BeginSigning(
			[]byte("%PDF-1.7\nminimal"),
			testConfig(),
			"B-B",
			nil,
			nowUnix,
			testEntropy(),
		); err != nil {
			t.Fatalf("BeginSigning(nowUnix=%d, entropy=16): %v", nowUnix, err)
		}
	}

	for name, test := range map[string]struct {
		nowUnix int64
		entropy []byte
		message string
	}{
		"year before 0000": {
			nowUnix: year0000Start - 1,
			entropy: testEntropy(),
			message: "invalid configuration: now_unix UTC year must be in 0000..=9999",
		},
		"year after 9999": {
			nowUnix: year9999End + 1,
			entropy: testEntropy(),
			message: "invalid configuration: now_unix UTC year must be in 0000..=9999",
		},
		"short entropy": {
			nowUnix: 1_700_000_000,
			entropy: make([]byte, 15),
			message: "invalid configuration: entropy must be at least 16 bytes",
		},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := BeginSigning(
				[]byte("%PDF-1.7\nminimal"),
				testConfig(),
				"B-B",
				nil,
				test.nowUnix,
				test.entropy,
			)
			if err == nil {
				t.Fatal("BeginSigning accepted invalid host context")
			}
			if err.Error() != test.message {
				t.Fatalf("error = %q, want %q", err, test.message)
			}
		})
	}
}
