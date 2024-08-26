module main

go 1.22.0

toolchain go1.22.4

require (
	github.com/google/go-tpm v0.9.2-0.20240625170440-991b038b62b6
	github.com/google/go-tpm-tools v0.4.4
	github.com/salrashid123/tink-go-tpm/v2 v2.0.0
	github.com/tink-crypto/tink-go/v2 v2.0.0

)

require (
	github.com/foxboron/go-tpm-keyfiles v0.0.0-20240805214234-f870d6f1ff68 // indirect
	github.com/tink-crypto/tink-go v0.0.0-20230613075026-d6de17e3f164 // indirect
	golang.org/x/crypto v0.19.0 // indirect
	golang.org/x/sys v0.21.0 // indirect
	google.golang.org/protobuf v1.31.0 // indirect
)

replace github.com/salrashid123/tink-go-tpm/v2 => ../
