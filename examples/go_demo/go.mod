module cleverbase-go-demo

go 1.22

require github.com/alkem-io/cleverbase-sdk/bindings/go v0.0.0

require (
	github.com/fxamacker/cbor/v2 v2.7.0 // indirect
	github.com/x448/float16 v0.8.4 // indirect
)

replace github.com/alkem-io/cleverbase-sdk/bindings/go => ../../bindings/go
