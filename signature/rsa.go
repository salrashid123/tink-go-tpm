package signature

import (
	"crypto"
	"crypto/rsa"
	"fmt"
	"hash"
	"math/big"

	keyfile "github.com/foxboron/go-tpm-keyfiles"
	"github.com/google/go-tpm/tpm2"
	tinktpmprotopb "github.com/salrashid123/tink-go-tpm/v2/proto"
	"github.com/tink-crypto/tink-go/v2/subtle"
	"github.com/tink-crypto/tink-go/v2/tink"
)

const (
	rsaMinModulusSizeInBits  = 2048
	rsaDefaultPublicExponent = 65537
)

// RSAValidModulusSizeInBits the size in bits for an RSA key.
func RSAValidModulusSizeInBits(m int) error {
	if m < rsaMinModulusSizeInBits {
		return fmt.Errorf("modulus size too small, must be >= %d", rsaMinModulusSizeInBits)
	}
	return nil
}

// RSAValidPublicExponent validates a public RSA exponent.
func RSAValidPublicExponent(e int) error {
	// crypto/rsa uses the following hardcoded public exponent value.
	if e != rsaDefaultPublicExponent {
		return fmt.Errorf("invalid public exponent")
	}
	return nil
}

// HashSafeForSignature checks whether a hash function is safe to use with digital signatures
// that require collision resistance.
func HashSafeForSignature(hashAlg string) error {
	switch hashAlg {
	case "SHA256", "SHA384", "SHA512":
		return nil
	default:
		return fmt.Errorf("hash function not safe for digital signatures: %q", hashAlg)
	}
}

const (
	testMsg          = "Tink and Wycheproof."
	signVerifyErrMsg = "signing with private key followed by verifying with public key failed, the key may be corrupted"
)

// Validate_RSA_SSA_PKCS1 validates that the corresponding private key is valid by signing and verifying a message.
func Validate_RSA_SSA_PKCS1(km tpmRSASSAPKCS1SignerKeyManager, hashAlg string, privKey keyfile.TPMKey) error {
	signer, err := New_RSA_SSA_PKCS1_Signer(km, hashAlg, privKey)
	if err != nil {
		return err
	}

	outPub, err := privKey.Pubkey.Contents()
	if err != nil {
		return err
	}

	rsaDetail, err := outPub.Parameters.RSADetail()
	if err != nil {
		return err
	}
	rsaUnique, err := outPub.Unique.RSA()
	if err != nil {
		return err
	}

	rsaPub, err := tpm2.RSAPub(rsaDetail, rsaUnique)
	if err != nil {
		return err
	}

	verifier, err := New_RSA_SSA_PKCS1_Verifier(hashAlg, *rsaPub)
	if err != nil {
		return err
	}
	if err := validateSignerVerifier(signer, verifier); err != nil {
		return fmt.Errorf("RSA-SSA-PKCS1: %q", signVerifyErrMsg)
	}
	return nil
}

func validateSignerVerifier(signer tink.Signer, verifier tink.Verifier) error {
	signature, err := signer.Sign([]byte(testMsg))
	if err != nil {
		return err
	}
	if err := verifier.Verify([]byte(signature), []byte(testMsg)); err != nil {
		return err
	}
	return nil
}

func validRSAPublicKey(rsaPub rsa.PublicKey) error {
	if err := RSAValidModulusSizeInBits(rsaPub.N.BitLen()); err != nil {
		return err
	}
	return RSAValidPublicExponent(rsaPub.E)
}

func hashID(hashAlg string) (crypto.Hash, error) {
	switch hashAlg {
	case "SHA256":
		return crypto.SHA256, nil
	case "SHA384":
		return crypto.SHA384, nil
	case "SHA512":
		return crypto.SHA512, nil
	default:
		return 0, fmt.Errorf("invalid hash function: %q", hashAlg)
	}
}

func rsaHashFunc(hashAlg string) (func() hash.Hash, crypto.Hash, error) {
	if err := HashSafeForSignature(hashAlg); err != nil {
		return nil, 0, err
	}
	hashFunc := subtle.GetHashFunc(hashAlg)
	if hashFunc == nil {
		return nil, 0, fmt.Errorf("invalid hash function: %q", hashAlg)
	}
	hashID, err := hashID(hashAlg)
	if err != nil {
		return nil, 0, err
	}
	return hashFunc, hashID, nil
}

func bytesToBigInt(val []byte) *big.Int {
	return new(big.Int).SetBytes(val)
}

func validateRSAPubKeyParams(h tinktpmprotopb.HashType, modSizeBits int, pubExponent []byte) error {
	if err := HashSafeForSignature(hashName(h)); err != nil {
		return err
	}
	if err := RSAValidModulusSizeInBits(modSizeBits); err != nil {
		return err
	}
	e := bytesToBigInt(pubExponent)
	if !e.IsInt64() {
		return fmt.Errorf("public exponent can't fit in a 64 bit integer")
	}
	return RSAValidPublicExponent(int(e.Int64()))
}

func hashName(h tinktpmprotopb.HashType) string {
	return tinktpmprotopb.HashType_name[int32(h)]
}
