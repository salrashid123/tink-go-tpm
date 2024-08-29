package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"slices"

	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpmutil"
	tpmsign "github.com/salrashid123/tink-go-tpm/v2/signature"

	tinkcommon "github.com/salrashid123/tink-go-tpm/v2/common"
	"github.com/tink-crypto/tink-go/v2/core/registry"
	"github.com/tink-crypto/tink-go/v2/insecurecleartextkeyset"
	"github.com/tink-crypto/tink-go/v2/keyset"
)

var (
	tpmPath   = flag.String("tpm-path", "127.0.0.1:2321", "Path to the TPM device (character device or a Unix socket).")
	plaintext = flag.String("plaintext", "this data needs to be signed", "plaintext to sign")

	publicKeySet  = flag.String("publicKeySet", "/tmp/public.json", "File to write the publci keysetto")
	privateKeySet = flag.String("privateKeySet", "/tmp/private.json", "File to write the private keyset to")

	signatureFile = flag.String("signatureFile", "/tmp/signature.dat", "File to write the signature to")
	dataFile      = flag.String("dataFile", "/tmp/data.txt", "File to write the data to sign to")
)

var TPMDEVICES = []string{"/dev/tpm0", "/dev/tpmrm0"}

func OpenTPM(path string) (io.ReadWriteCloser, error) {
	if slices.Contains(TPMDEVICES, path) {
		return tpmutil.OpenTPM(path)
	} else if path == "simulator" {
		return simulator.GetWithFixedSeedInsecure(1073741825)
	} else {
		return net.Dial("tcp", path)
	}
}

func main() {
	flag.Parse()
	rwc, err := OpenTPM(*tpmPath)
	if err != nil {
		log.Fatalf("can't open TPM %q: %v", *tpmPath, err)
	}
	defer func() {
		if err := rwc.Close(); err != nil {
			log.Fatalf("can't close TPM %q: %v", *tpmPath, err)
		}
	}()

	rwr := transport.FromReadWriter(rwc)

	sess, cleanup1, err := tpm2.PolicySession(rwr, tpm2.TPMAlgSHA256, 16, tpm2.Trial())
	if err != nil {
		log.Fatal(err)
	}

	defer cleanup1()

	pav := tpm2.PolicyAuthValue{
		PolicySession: sess.Handle(),
	}
	_, err = pav.Execute(rwr)
	if err != nil {
		log.Fatal(err)
	}

	pgd, err := tpm2.PolicyGetDigest{
		PolicySession: sess.Handle(),
	}.Execute(rwr)
	if err != nil {
		log.Fatal(err)
	}

	se, err := tinkcommon.NewPasswordSession(rwr, nil, nil, pgd.PolicyDigest.Buffer)
	if err != nil {
		log.Fatal(err)
	}

	rsaKeyManager := tpmsign.NewRSASSAPKCS1SignerTpmKeyManager(rwc, se)
	err = registry.RegisterKeyManager(rsaKeyManager)
	if err != nil {
		log.Println(err)
	}

	kh, err := keyset.NewHandle(tpmsign.RSA_SSA_PKCS1_2048_SHA256_F4_Key_Template()) // Other key templates can also be used.
	if err != nil {
		log.Fatal(err)
	}

	s, err := tpmsign.NewSigner(kh)
	if err != nil {
		log.Fatal(err)
	}

	msg := []byte(*plaintext)
	sig, err := s.Sign(msg)
	if err != nil {
		log.Fatal(err)
	}

	// private

	bufpriv := new(bytes.Buffer)
	wpriv := keyset.NewJSONWriter(bufpriv)
	err = insecurecleartextkeyset.Write(kh, wpriv)
	if err != nil {
		log.Fatal(err)
	}

	var prettyJSONPriv bytes.Buffer
	error := json.Indent(&prettyJSONPriv, bufpriv.Bytes(), "", "\t")
	if error != nil {
		log.Fatalf("JSON parse error: %v ", error)
	}

	log.Println("Tink Private Keyset:\n", prettyJSONPriv.String())

	// publci
	pubkh, err := kh.Public()
	if err != nil {
		log.Fatal(err)
	}

	bufpub := new(bytes.Buffer)
	wpub := keyset.NewJSONWriter(bufpub)
	err = insecurecleartextkeyset.Write(pubkh, wpub)
	if err != nil {
		log.Fatal(err)
	}

	var prettyJSONPub bytes.Buffer
	error = json.Indent(&prettyJSONPub, bufpub.Bytes(), "", "\t")
	if error != nil {
		log.Fatalf("JSON parse error: %v ", error)
	}

	log.Println("Tink Public Keyset:\n", prettyJSONPub.String())

	fmt.Printf("Message: %s\n", msg)
	fmt.Printf("Signature: %s\n", base64.StdEncoding.EncodeToString(sig))

	rsaVerifierKeyManager := tpmsign.NewRSASSAPKCS1VerifierTpmKeyManager(nil, nil)
	err = registry.RegisterKeyManager(rsaVerifierKeyManager)
	if err != nil {
		log.Println(err)
	}

	err = os.WriteFile(*dataFile, []byte(*plaintext), 0644)
	if err != nil {
		log.Fatal(err)
	}

	err = os.WriteFile(*signatureFile, []byte(sig), 0644)
	if err != nil {
		log.Fatal(err)
	}

	err = os.WriteFile(*privateKeySet, prettyJSONPriv.Bytes(), 0644)
	if err != nil {
		log.Fatal(err)
	}

	err = os.WriteFile(*publicKeySet, prettyJSONPub.Bytes(), 0644)
	if err != nil {
		log.Fatal(err)
	}

	// v, err := tpmsign.NewVerifier(pubkh)
	// if err != nil {
	// 	log.Fatal(err)
	// }
	// if err := v.Verify(sig, msg); err != nil {
	// 	log.Fatal(err)
	// }

	// fmt.Println("Verified")
}
