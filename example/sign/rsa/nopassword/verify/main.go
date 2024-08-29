package main

import (
	"bytes"
	"flag"
	"fmt"
	"log"
	"os"

	tpmsign "github.com/salrashid123/tink-go-tpm/v2/signature"

	"github.com/tink-crypto/tink-go/v2/core/registry"
	"github.com/tink-crypto/tink-go/v2/insecurecleartextkeyset"
	"github.com/tink-crypto/tink-go/v2/keyset"
)

var (
	publicKeySet = flag.String("publicKeySet", "/tmp/public.json", "File to write the publci keysetto")

	signatureFile = flag.String("signatureFile", "/tmp/signature.dat", "File to write the signature to")
	dataFile      = flag.String("dataFile", "/tmp/data.txt", "File to write the data to sign to")
)

func main() {
	flag.Parse()
	msg, err := os.ReadFile(*dataFile)
	if err != nil {
		log.Fatal(err)
	}

	sig, err := os.ReadFile(*signatureFile)
	if err != nil {
		log.Fatal(err)
	}

	ksf, err := os.ReadFile(*publicKeySet)
	if err != nil {
		log.Fatal(err)

	}

	ksr := keyset.NewJSONReader(bytes.NewBuffer(ksf))

	pubkh, err := insecurecleartextkeyset.Read(ksr)
	if err != nil {
		log.Fatal(err)
	}

	rsaVerifierKeyManager := tpmsign.NewRSASSAPKCS1VerifierTpmKeyManager(nil, nil)
	err = registry.RegisterKeyManager(rsaVerifierKeyManager)
	if err != nil {
		log.Fatal(err)
	}

	v, err := tpmsign.NewVerifier(pubkh)
	if err != nil {
		log.Fatal(err)
	}
	if err := v.Verify(sig, msg); err != nil {
		log.Fatal(err)
	}

	fmt.Println("Verified")
}
