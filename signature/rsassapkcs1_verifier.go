package signature

import (
	"crypto"
	"crypto/rsa"
	"hash"

	"github.com/tink-crypto/tink-go/v2/subtle"
	"github.com/tink-crypto/tink-go/v2/tink"
)

// RSA_SSA_PKCS1_Verifier is an implementation of Verifier for RSA-SSA-PKCS1.
type RSA_SSA_PKCS1_TPM_Verifier struct {
	publicKey rsa.PublicKey
	hashFunc  func() hash.Hash
	hashID    crypto.Hash
}

var _ tink.Verifier = (*RSA_SSA_PKCS1_TPM_Verifier)(nil)

// New_RSA_SSA_PKCS1_Verifier creates a new intance of RSASSAPKCS1Verifier.
func New_RSA_SSA_PKCS1_Verifier(hashAlg string, pubKey rsa.PublicKey) (*RSA_SSA_PKCS1_TPM_Verifier, error) {
	if err := validRSAPublicKey(pubKey); err != nil {
		return nil, err
	}
	hashFunc, hashID, err := rsaHashFunc(hashAlg)
	if err != nil {
		return nil, err
	}
	return &RSA_SSA_PKCS1_TPM_Verifier{
		publicKey: pubKey,
		hashFunc:  hashFunc,
		hashID:    hashID,
	}, nil
}

// Verify verifies whether the given signaure is valid for the given data.
// It returns an error if the signature is not valid; nil otherwise.
func (v *RSA_SSA_PKCS1_TPM_Verifier) Verify(signature, data []byte) error {
	hashed, err := subtle.ComputeHash(v.hashFunc, data)
	if err != nil {
		return err
	}
	return rsa.VerifyPKCS1v15(&v.publicKey, v.hashID, hashed, signature)
}
