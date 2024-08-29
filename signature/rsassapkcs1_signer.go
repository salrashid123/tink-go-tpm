package signature

import (
	"crypto"
	"fmt"
	"hash"

	keyfile "github.com/foxboron/go-tpm-keyfiles"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/tink-crypto/tink-go/v2/subtle"
	"github.com/tink-crypto/tink-go/v2/tink"
)

// RSA_SSA_PKCS1_Signer is an implementation of Signer for RSA-SSA-PKCS1.
type RSA_SSA_PKCS1_TPM_Signer struct {
	km         tpmRSASSAPKCS1SignerKeyManager
	privateKey keyfile.TPMKey
	hashFunc   func() hash.Hash
	hashID     crypto.Hash
}

var _ (tink.Signer) = (*RSA_SSA_PKCS1_TPM_Signer)(nil)

// New_RSA_SSA_PKCS1_Signer creates a new intance of RSA_SSA_PKCS1_Signer.
func New_RSA_SSA_PKCS1_Signer(km tpmRSASSAPKCS1SignerKeyManager, hashAlg string, privKey keyfile.TPMKey) (*RSA_SSA_PKCS1_TPM_Signer, error) {

	outPub, err := privKey.Pubkey.Contents()
	if err != nil {
		return nil, err
	}

	rsaDetail, err := outPub.Parameters.RSADetail()
	if err != nil {
		return nil, err
	}
	rsaUnique, err := outPub.Unique.RSA()
	if err != nil {
		return nil, err
	}

	rsaPub, err := tpm2.RSAPub(rsaDetail, rsaUnique)
	if err != nil {
		return nil, err
	}

	if err := validRSAPublicKey(*rsaPub); err != nil {
		return nil, err
	}
	hashFunc, hashID, err := rsaHashFunc(hashAlg)
	if err != nil {
		return nil, err
	}
	return &RSA_SSA_PKCS1_TPM_Signer{
		km:         km,
		privateKey: privKey,
		hashFunc:   hashFunc,
		hashID:     hashID,
	}, nil
}

// Sign computes a signature for the given data.
func (s *RSA_SSA_PKCS1_TPM_Signer) Sign(data []byte) ([]byte, error) {
	digest, err := subtle.ComputeHash(s.hashFunc, data)
	if err != nil {
		return nil, err
	}

	rwr := transport.FromReadWriter(s.km.TpmDevice)
	cPrimary, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHOwner,
			Name:   tpm2.HandleName(tpm2.TPMRHOwner),
			Auth:   tpm2.PasswordAuth(s.km.AuthCallback.GetOwnerPassword()),
		},
		InPublic: tpm2.New2B(keyfile.ECCSRK_H2_Template),
	}.Execute(rwr)
	if err != nil {
		return nil, err
	}
	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: cPrimary.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(rwr)
	}()

	kf, err := keyfile.Decode(s.privateKey.Bytes())
	if err != nil {
		return nil, err
	}
	rsaKeyResponse, err := tpm2.Load{
		ParentHandle: tpm2.NamedHandle{
			Handle: cPrimary.ObjectHandle,
			Name:   cPrimary.Name,
		},
		InPrivate: kf.Privkey,
		InPublic:  kf.Pubkey,
	}.Execute(rwr)
	if err != nil {
		return nil, err
	}
	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: rsaKeyResponse.ObjectHandle,
		}
		_, err = flushContextCmd.Execute(rwr)
	}()

	se, c, err := s.km.AuthCallback.GetSession()
	if err != nil {
		return nil, err
	}
	defer c()

	var tpmHash tpm2.TPMAlgID
	switch h := s.hashID; h {
	case crypto.SHA256:
		tpmHash = tpm2.TPMAlgSHA256
	case crypto.SHA512:
		tpmHash = tpm2.TPMAlgSHA512
	default:
		tpmHash = tpm2.TPMAlgSHA256
	}

	rspSign, err := tpm2.Sign{
		KeyHandle: tpm2.AuthHandle{
			Handle: rsaKeyResponse.ObjectHandle,
			Name:   rsaKeyResponse.Name,
			Auth:   se,
		},
		Digest: tpm2.TPM2BDigest{
			Buffer: digest[:],
		},
		InScheme: tpm2.TPMTSigScheme{
			Scheme: tpm2.TPMAlgRSASSA,
			Details: tpm2.NewTPMUSigScheme(
				tpm2.TPMAlgRSASSA,
				&tpm2.TPMSSchemeHash{
					HashAlg: tpmHash,
				},
			),
		},
		Validation: tpm2.TPMTTKHashCheck{
			Tag: tpm2.TPMSTHashCheck,
		},
	}.Execute(rwr)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}

	var rsig *tpm2.TPMSSignatureRSA
	if rspSign.Signature.SigAlg == tpm2.TPMAlgRSASSA {
		rsig, err = rspSign.Signature.Signature.RSASSA()
		if err != nil {
			return nil, err
		}
	} else if rspSign.Signature.SigAlg == tpm2.TPMAlgRSAPSS {
		rsig, err = rspSign.Signature.Signature.RSAPSS()
		if err != nil {
			return nil, err
		}
	} else {
		return nil, err
	}

	return rsig.Sig.Buffer, nil

}
