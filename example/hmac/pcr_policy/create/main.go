package main

import (
	"bytes"
	"encoding/base64"
	"flag"
	"io"
	"log"
	"net"
	"os"
	"slices"
	"strconv"
	"strings"

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

var (
	tpmPath   = flag.String("tpm-path", "127.0.0.1:2321", "Path to the TPM device (character device or a Unix socket).")
	plaintext = flag.String("plaintext", "foo", "plaintext to mac")
	pcrList   = flag.String("pcrList", "", "SHA256 PCR Values to seal against 16,23")
	macFile   = flag.String("macFile", "mac.dat", "File to write the mac to")
	keySet    = flag.String("keySet", "keyset.json", "File to write the keyset to")
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
	//ctx := context.Background()

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

	var pcrs []uint
	pcrsStr := strings.Split(*pcrList, ",")
	for _, v := range pcrsStr {
		uv, err := strconv.ParseUint(v, 10, 32)
		if err != nil {
			log.Fatalf("can't open TPM %q: %v", *tpmPath, err)
		}
		pcrs = append(pcrs, uint(uv))
	}

	sel := tpm2.TPMLPCRSelection{
		PCRSelections: []tpm2.TPMSPCRSelection{
			{
				Hash:      tpm2.TPMAlgSHA256,
				PCRSelect: tpm2.PCClientCompatible.PCRs(pcrs...),
			},
		},
	}

	sess, cleanup1, err := tpm2.PolicySession(rwr, tpm2.TPMAlgSHA256, 16, tpm2.Trial())
	if err != nil {
		log.Println(err)
		return 1
	}

	defer cleanup1()

	pav := tpm2.PolicyPCR{
		PolicySession: sess.Handle(),
		Pcrs:          sel,
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

	se, err := tinkcommon.NewPCRSession(rwr, nil, nil, pgd.PolicyDigest.Buffer, sel.PCRSelections, nil)
	if err != nil {
		log.Println(err)
		return 1
	}

	hmacKeyManager := tpmmac.NewTPMHMACKeyManager(rwc, se)

	err = registry.RegisterKeyManager(hmacKeyManager)
	if err != nil {
		log.Println(err)
		return 1
	}

	kh1, err := keyset.NewHandle(tpmmac.HMACSHA256Tag256KeyTPMTemplate())

	if err != nil {
		log.Println(err)
		return 1
	}

	a, err := mac.New(kh1)
	if err != nil {
		log.Println(err)
		return 1
	}

	tag, err := a.ComputeMAC([]byte(*plaintext))
	if err != nil {
		log.Println(err)
		return 1
	}
	log.Printf("    MAC %s\n", base64.RawStdEncoding.EncodeToString(tag))

	buf := new(bytes.Buffer)
	w := keyset.NewJSONWriter(buf)

	err = insecurecleartextkeyset.Write(kh1, w)
	if err != nil {
		log.Println(err)
		return 1
	}

	err = os.WriteFile(*macFile, tag, 0644)
	if err != nil {
		log.Println(err)
		return 1
	}

	err = os.WriteFile(*keySet, buf.Bytes(), 0644)
	if err != nil {
		log.Println(err)
		return 1
	}

	return 0
}

func main() {
	flag.Parse()
	os.Exit(run())
}
