package common

import (
	"io"
	"net"
	"slices"

	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpmutil"
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

const (
	TPMKeyVersion = 0
)

func getExpectedPCRDigest(thetpm transport.TPM, selection tpm2.TPMLPCRSelection, hashAlg tpm2.TPMAlgID) ([]byte, error) {
	pcrRead := tpm2.PCRRead{
		PCRSelectionIn: selection,
	}

	pcrReadRsp, err := pcrRead.Execute(thetpm)
	if err != nil {
		return nil, err
	}

	var expectedVal []byte
	for _, digest := range pcrReadRsp.PCRValues.Digests {
		expectedVal = append(expectedVal, digest.Buffer...)
	}

	cryptoHashAlg, err := hashAlg.Hash()
	if err != nil {
		return nil, err
	}

	hash := cryptoHashAlg.New()
	hash.Write(expectedVal)
	return hash.Sum(nil), nil
}

type AuthCallback interface {
	GetSession() (auth tpm2.Session, closer func() error, err error) // this supplies the session handle to the library
	GetPassword() []byte
	GetOwnerPassword() []byte
	GetPolicyDigest() []byte
}

// for pcr sessions
type PCRCallback struct {
	rwr           transport.TPM
	sel           []tpm2.TPMSPCRSelection
	password      []byte
	ownerpassword []byte
	policydigest  []byte
	pcrdigest     []byte
}

func NewPCRSession(rwr transport.TPM, password []byte, ownerpassword []byte, policyDigest []byte, sel []tpm2.TPMSPCRSelection, pcrDigest []byte) (PCRCallback, error) {
	return PCRCallback{rwr, sel, password, ownerpassword, policyDigest, pcrDigest}, nil
}

func (p PCRCallback) GetSession() (auth tpm2.Session, closer func() error, err error) {
	sess, closer, err := tpm2.PolicySession(p.rwr, tpm2.TPMAlgSHA256, 16)
	if err != nil {
		return nil, nil, err
	}
	_, err = tpm2.PolicyPCR{
		PolicySession: sess.Handle(),
		// PcrDigest: tpm2.TPM2BDigest{
		// 	Buffer: p.pcrdigest,
		// },
		Pcrs: tpm2.TPMLPCRSelection{
			PCRSelections: p.sel,
		},
	}.Execute(p.rwr)
	if err != nil {
		return nil, nil, err
	}
	return sess, closer, nil
}

func (p PCRCallback) GetPassword() []byte {
	return p.password
}

func (p PCRCallback) GetOwnerPassword() []byte {
	return p.ownerpassword
}

func (p PCRCallback) GetPolicyDigest() []byte {
	return p.policydigest
}

func (p PCRCallback) GetPCRDigest() []byte {
	return p.pcrdigest
}

// for password sessions
type PasswordCallback struct {
	rwr           transport.TPM
	password      []byte
	ownerpassword []byte
	policydigest  []byte
}

func NewPasswordSession(rwr transport.TPM, password []byte, ownerpassword []byte, policyDigest []byte) (PasswordCallback, error) {
	return PasswordCallback{rwr, password, ownerpassword, policyDigest}, nil
}

func (p PasswordCallback) GetSession() (auth tpm2.Session, closer func() error, err error) {
	c := func() error { return nil }
	return tpm2.PasswordAuth(p.password), c, nil
}

func (p PasswordCallback) GetPassword() []byte {
	return p.password
}

func (p PasswordCallback) GetOwnerPassword() []byte {
	return p.ownerpassword
}

func (p PasswordCallback) GetPolicyDigest() []byte {
	return p.policydigest
}
