module main

go 1.22

toolchain go1.22.4

require (
	github.com/google/go-tpm-tools v0.3.13-0.20230620182252-4639ecce2aba
	github.com/salrashid123/tink-go-tpm/v2 v2.0.0
	github.com/tink-crypto/tink-go/v2 v2.0.0

)

require (
	github.com/google/go-tpm v0.9.2-0.20240625151120-98efb9720c4f // indirect
	golang.org/x/crypto v0.14.0 // indirect
	golang.org/x/sys v0.13.0 // indirect
	google.golang.org/protobuf v1.31.0 // indirect
)

replace github.com/salrashid123/tink-go-tpm/v2 => ../
