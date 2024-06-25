package main

import (
	"bytes"
	"flag"
	"io"
	"log"
	"net"
	"os"
	"slices"

	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpmutil"
	tinktpm "github.com/salrashid123/tink-go-tpm/v2"
	tinkcommon "github.com/salrashid123/tink-go-tpm/v2/common"
	"github.com/tink-crypto/tink-go/v2/core/registry"
	"github.com/tink-crypto/tink-go/v2/insecurecleartextkeyset"
	"github.com/tink-crypto/tink-go/v2/mac"

	"github.com/tink-crypto/tink-go/v2/keyset"
)

const ()

var (
	tpmPath   = flag.String("tpm-path", "/dev/tpmrm0", "Path to the TPM device (character device or a Unix socket).")
	plaintext = flag.String("plaintext", "foo", "plaintext to mac")

	macFile = flag.String("macFile", "mac.dat", "File to write the mac to")
	keySet  = flag.String("keySet", "keyset.json", "File to write the keyset to")
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

func run() int {
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
		log.Println(err)
		return 1
	}

	defer cleanup1()

	pav := tpm2.PolicyAuthValue{
		PolicySession: sess.Handle(),
	}
	_, err = pav.Execute(rwr)
	if err != nil {
		log.Println(err)
		return 1
	}

	pgd, err := tpm2.PolicyGetDigest{
		PolicySession: sess.Handle(),
	}.Execute(rwr)
	if err != nil {
		log.Println(err)
		return 1
	}

	se, err := tinkcommon.NewPasswordSession(rwr, nil, pgd.PolicyDigest.Buffer, nil)
	if err != nil {
		log.Println(err)
		return 1
	}

	hmacKeyManager := tinktpm.NewTPMHMACKeyManager(rwc, se)

	err = registry.RegisterKeyManager(hmacKeyManager)
	if err != nil {
		log.Println(err)
		return 1
	}

	mf, err := os.ReadFile(*macFile)
	if err != nil {
		log.Println(err)
		return 1
	}

	ksf, err := os.ReadFile(*keySet)
	if err != nil {
		log.Println(err)
		return 1
	}

	ksr := keyset.NewJSONReader(bytes.NewBuffer(ksf))

	kh, err := insecurecleartextkeyset.Read(ksr)
	if err != nil {
		log.Println(err)
		return 1
	}

	av, err := mac.New(kh)
	if err != nil {
		log.Println(err)
		return 1
	}

	err = av.VerifyMAC(mf, []byte(*plaintext))
	if err != nil {
		log.Println(err)
		return 1
	}
	log.Println("Verified")

	return 0
}

func main() {
	flag.Parse()
	os.Exit(run())
}
