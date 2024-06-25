package common

import (
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

var (
	ECCSRKH2Template = tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgECC,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:            true,
			FixedParent:         true,
			SensitiveDataOrigin: true,
			UserWithAuth:        true,
			NoDA:                true,
			Restricted:          true,
			Decrypt:             true,
		},
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgECC,
			&tpm2.TPMSECCParms{
				Symmetric: tpm2.TPMTSymDefObject{
					Algorithm: tpm2.TPMAlgAES,
					KeyBits: tpm2.NewTPMUSymKeyBits(
						tpm2.TPMAlgAES,
						tpm2.TPMKeyBits(128),
					),
					Mode: tpm2.NewTPMUSymMode(
						tpm2.TPMAlgAES,
						tpm2.TPMAlgCFB,
					),
				},
				CurveID: tpm2.TPMECCNistP256,
			},
		),
		Unique: tpm2.NewTPMUPublicID(
			tpm2.TPMAlgECC,
			&tpm2.TPMSECCPoint{
				X: tpm2.TPM2BECCParameter{
					Buffer: make([]byte, 0),
				},
				Y: tpm2.TPM2BECCParameter{
					Buffer: make([]byte, 0),
				},
			},
		),
	}
)

func pcrPolicyDigest(thetpm transport.TPM, pcr []uint) ([]byte, error) {
	sess, cleanup, err := tpm2.PolicySession(thetpm, tpm2.TPMAlgSHA256, 16, tpm2.Trial())
	if err != nil {
		return nil, err
	}
	defer cleanup()

	selection := tpm2.TPMLPCRSelection{
		PCRSelections: []tpm2.TPMSPCRSelection{
			{
				Hash:      tpm2.TPMAlgSHA256,
				PCRSelect: tpm2.PCClientCompatible.PCRs(pcr...),
			},
		},
	}
	expectedDigest, err := getExpectedPCRDigest(thetpm, selection, tpm2.TPMAlgSHA256)
	if err != nil {
		return nil, err
	}
	_, err = tpm2.PolicyPCR{
		PolicySession: sess.Handle(),
		Pcrs:          selection,
		PcrDigest: tpm2.TPM2BDigest{
			Buffer: expectedDigest,
		},
	}.Execute(thetpm)
	if err != nil {
		return nil, err
	}

	pgd, err := tpm2.PolicyGetDigest{
		PolicySession: sess.Handle(),
	}.Execute(thetpm)
	if err != nil {
		return nil, err
	}
	_, err = tpm2.FlushContext{FlushHandle: sess.Handle()}.Execute(thetpm)
	if err != nil {
		return nil, err
	}
	return pgd.PolicyDigest.Buffer, nil
}

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
	GetPolicyDigest() []byte
	GetSensitive() []byte
}

// for pcr sessions
type PCRCallback struct {
	rwr          transport.TPM
	sel          []tpm2.TPMSPCRSelection
	password     []byte
	policydigest []byte
	sensitive    []byte
}

func NewPCRSession(rwr transport.TPM, password []byte, policyDigest []byte, sensitive []byte, sel []tpm2.TPMSPCRSelection) (PCRCallback, error) {
	return PCRCallback{rwr, sel, password, policyDigest, sensitive}, nil
}

func (p PCRCallback) GetSession() (auth tpm2.Session, closer func() error, err error) {
	sess, closer, err := tpm2.PolicySession(p.rwr, tpm2.TPMAlgSHA256, 16)
	if err != nil {
		return nil, nil, err
	}
	_, err = tpm2.PolicyPCR{
		PolicySession: sess.Handle(),
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

func (p PCRCallback) GetPolicyDigest() []byte {
	return p.policydigest
}

func (p PCRCallback) GetSensitive() []byte {
	return p.sensitive
}

// for password sessions
type PasswordCallback struct {
	rwr          transport.TPM
	password     []byte
	policydigest []byte
	sensitive    []byte
}

func NewPasswordSession(rwr transport.TPM, password []byte, policyDigest []byte, sensitive []byte) (PasswordCallback, error) {
	return PasswordCallback{rwr, password, policyDigest, sensitive}, nil
}

func (p PasswordCallback) GetSession() (auth tpm2.Session, closer func() error, err error) {
	c := func() error { return nil }
	return tpm2.PasswordAuth(p.password), c, nil
}

func (p PasswordCallback) GetPassword() []byte {
	return p.password
}

func (p PasswordCallback) GetPolicyDigest() []byte {
	return p.policydigest
}

func (p PasswordCallback) GetSensitive() []byte {
	return p.sensitive
}
