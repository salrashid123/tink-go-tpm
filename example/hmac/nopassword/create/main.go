package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
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
	tinkcommon "github.com/salrashid123/tink-go-tpm/v2/common"
	tpmmac "github.com/salrashid123/tink-go-tpm/v2/mac"
	"github.com/tink-crypto/tink-go/v2/core/registry"
	"github.com/tink-crypto/tink-go/v2/insecurecleartextkeyset"
	"github.com/tink-crypto/tink-go/v2/mac"

	"github.com/tink-crypto/tink-go/v2/keyset"
)

const ()

var (
	tpmPath   = flag.String("tpm-path", "127.0.0.1:2321", "Path to the TPM device (character device or a Unix socket).")
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
		log.Fatalln(err)
	}

	defer cleanup1()

	pav := tpm2.PolicyAuthValue{
		PolicySession: sess.Handle(),
	}
	_, err = pav.Execute(rwr)
	if err != nil {
		log.Fatalln(err)
	}

	pgd, err := tpm2.PolicyGetDigest{
		PolicySession: sess.Handle(),
	}.Execute(rwr)
	if err != nil {
		log.Fatalln(err)
	}

	se, err := tinkcommon.NewPasswordSession(rwr, nil, nil, pgd.PolicyDigest.Buffer)
	if err != nil {
		log.Fatalln(err)
	}

	hmacKeyManager := tpmmac.NewTPMHMACKeyManager(rwc, se)
	err = registry.RegisterKeyManager(hmacKeyManager)
	if err != nil {
		log.Fatalln(err)
	}

	kh1, err := keyset.NewHandle(tpmmac.HMACSHA256Tag256KeyTPMTemplate())
	//kh1, err := keyset.NewHandle(tpmmac.HMACSHA256Tag256KeyTPMNoPrefixTemplate())
	//kh1, err := keyset.NewHandle(tpmmac.HMACSHA512Tag256KeyTPMTemplate())
	if err != nil {
		log.Fatalln(err)
	}

	a, err := mac.New(kh1)
	if err != nil {
		log.Fatalln(err)
	}

	tag, err := a.ComputeMAC([]byte(*plaintext))
	if err != nil {
		log.Fatalln(err)
	}

	log.Printf("    MAC %s\n", base64.RawStdEncoding.EncodeToString(tag))

	buf := new(bytes.Buffer)
	w := keyset.NewJSONWriter(buf)

	err = insecurecleartextkeyset.Write(kh1, w)
	if err != nil {
		log.Fatalln(err)
	}

	err = os.WriteFile(*macFile, tag, 0644)
	if err != nil {
		log.Fatalln(err)
	}

	var prettyJSON bytes.Buffer
	err = json.Indent(&prettyJSON, buf.Bytes(), "", "\t")
	if err != nil {
		log.Fatalln(err)
	}

	log.Printf("Tink Keyset: \n%s\n", prettyJSON.String())

	err = os.WriteFile(*keySet, buf.Bytes(), 0644)
	if err != nil {
		log.Fatalln(err)
	}

}
