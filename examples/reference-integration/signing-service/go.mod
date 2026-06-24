module github.com/alkem-io/cleverbase-sdk/examples/reference-integration/signing-service

go 1.22

replace github.com/alkem-io/cleverbase-sdk/bindings/go => ../../../bindings/go

require (
	github.com/alkem-io/cleverbase-sdk/bindings/go v0.0.0-00010101000000-000000000000
	github.com/fxamacker/cbor/v2 v2.9.2
)

require (
	github.com/alkem-io/cleverbase-sdk/examples/reference-integration/mock-upstream v0.0.0
	github.com/x448/float16 v0.8.4 // indirect
)

replace github.com/alkem-io/cleverbase-sdk/examples/reference-integration/mock-upstream => ../mock-upstream
