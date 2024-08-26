package subtle

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"

	keyfile "github.com/foxboron/go-tpm-keyfiles"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"

	tinkcommon "github.com/salrashid123/tink-go-tpm/v2/common"
	tinktpmprotopb "github.com/salrashid123/tink-go-tpm/v2/proto"
)

const (
	// AESCTRMinIVSize is the minimum IV size that this implementation supports.
	AESCTRMinIVSize = 12
	intSize         = 32 << (^uint(0) >> 63) // 32 or 64
	maxInt          = 1<<(intSize-1) - 1
)

// AESCTR is an implementation of AEAD interface.
type TpmAesCtr struct {
	TPMDevice   io.ReadWriteCloser
	ctx         context.Context
	Key         tinktpmprotopb.AesCtrTpmKey
	AuthSession tinkcommon.AuthCallback
	KeyFormat   tinktpmprotopb.AesCtrTpmKeyFormat
	rwr         transport.TPM
	kf          *keyfile.TPMKey
}

var ()

const maxDigestBuffer = 1024

func NewTPMAESCTR(ctx context.Context, conf *TpmAesCtr) (*TpmAesCtr, error) {

	conf.ctx = ctx
	conf.rwr = transport.FromReadWriter(conf.TPMDevice)

	if !bytes.Equal(conf.Key.PolicyDigest, conf.AuthSession.GetPolicyDigest()) {
		return nil, fmt.Errorf("error creating key: policy digest mismatch in key %s, in session: %s", hex.EncodeToString(conf.Key.PolicyDigest), hex.EncodeToString(conf.AuthSession.GetPolicyDigest()))
	}

	kf, err := keyfile.Decode(conf.Key.Keyfile)
	if err != nil {
		return nil, err
	}

	conf.kf = kf

	return conf, nil
}

func (a *TpmAesCtr) Encrypt(plaintext []byte) ([]byte, error) {
	if len(plaintext) > maxInt-int(a.KeyFormat.IvSize) {
		return nil, fmt.Errorf("aes_ctr: plaintext too long")
	}
	var err error

	// todo, provide a way to acquire any ownerpassword, if set
	cPrimary, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHOwner,
			Name:   tpm2.HandleName(tpm2.TPMRHOwner),
			Auth:   tpm2.PasswordAuth(a.AuthSession.GetOwnerPassword()),
		},
		InPublic: tpm2.New2B(keyfile.ECCSRK_H2_Template),
	}.Execute(a.rwr)
	if err != nil {
		return nil, err
	}
	defer func() {
		flush := tpm2.FlushContext{
			FlushHandle: cPrimary.ObjectHandle,
		}
		_, err = flush.Execute(a.rwr)
	}()

	k, err := tpm2.Load{
		ParentHandle: tpm2.AuthHandle{
			Handle: cPrimary.ObjectHandle,
			Name:   cPrimary.Name,
			Auth:   tpm2.PasswordAuth(nil),
		},
		InPublic:  a.kf.Pubkey,
		InPrivate: a.kf.Privkey,
	}.Execute(a.rwr)
	if err != nil {
		return nil, err
	}
	defer func() {
		flush := tpm2.FlushContext{
			FlushHandle: k.ObjectHandle,
		}
		_, err = flush.Execute(a.rwr)
	}()

	iv := make([]byte, a.KeyFormat.IvSize)
	_, err = io.ReadFull(rand.Reader, iv)
	if err != nil {
		return nil, err
	}

	se, closer, err := a.AuthSession.GetSession()
	if err != nil {
		return nil, err
	}
	defer closer()

	keyAuth := tpm2.AuthHandle{
		Handle: k.ObjectHandle,
		Name:   k.Name,
		Auth:   se,
	}
	encrypted, err := encryptDecryptSymmetric(a.rwr, keyAuth, iv, plaintext, false)
	if err != nil {
		return nil, err
	}
	ciphertext := append(iv, encrypted...)

	return ciphertext, nil
}

// ValidateAESKeySize checks if the given key size is a valid AES key size.
// https://github.com/tink-crypto/tink-go/blob/main/aead/subtle/subtle.go#L26
func validateAESKeySize(sizeInBytes uint32) error {
	switch sizeInBytes {
	case 16, 32:
		return nil
	default:
		return fmt.Errorf("invalid AES key size; want 16 or 32, got %d", sizeInBytes)
	}
}

// Decrypt decrypts ciphertext.
func (a *TpmAesCtr) Decrypt(ciphertext []byte) ([]byte, error) {

	if len(ciphertext) < int(a.KeyFormat.IvSize) {
		return nil, fmt.Errorf("aes_ctr: ciphertext too short")
	}

	iv := ciphertext[:a.KeyFormat.IvSize]

	cPrimary, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHOwner,
			Name:   tpm2.HandleName(tpm2.TPMRHOwner),
			Auth:   tpm2.PasswordAuth(a.AuthSession.GetOwnerPassword()),
		},
		InPublic: tpm2.New2B(keyfile.ECCSRK_H2_Template),
	}.Execute(a.rwr)
	if err != nil {
		return nil, err
	}
	defer func() {
		flush := tpm2.FlushContext{
			FlushHandle: cPrimary.ObjectHandle,
		}
		_, err = flush.Execute(a.rwr)
	}()

	k, err := tpm2.Load{
		ParentHandle: tpm2.AuthHandle{
			Handle: cPrimary.ObjectHandle,
			Name:   cPrimary.Name,
			Auth:   tpm2.PasswordAuth(nil),
		},
		InPublic:  a.kf.Pubkey,
		InPrivate: a.kf.Privkey,
	}.Execute(a.rwr)
	if err != nil {
		return nil, err
	}
	defer func() {
		flush := tpm2.FlushContext{
			FlushHandle: k.ObjectHandle,
		}
		_, err = flush.Execute(a.rwr)
	}()

	se, closer, err := a.AuthSession.GetSession()
	if err != nil {
		return nil, err
	}
	defer closer()

	keyAuth := tpm2.AuthHandle{
		Handle: k.ObjectHandle,
		Name:   k.Name,
		Auth:   se,
	}

	return encryptDecryptSymmetric(a.rwr, keyAuth, iv, ciphertext[a.KeyFormat.IvSize:], true)
}

func encryptDecryptSymmetric(rwr transport.TPM, keyAuth tpm2.AuthHandle, iv, data []byte, decrypt bool) ([]byte, error) {
	var out, block []byte

	for rest := data; len(rest) > 0; {
		if len(rest) > maxDigestBuffer {
			block, rest = rest[:maxDigestBuffer], rest[maxDigestBuffer:]
		} else {
			block, rest = rest, nil
		}
		r, err := tpm2.EncryptDecrypt2{
			KeyHandle: keyAuth,
			Message: tpm2.TPM2BMaxBuffer{
				Buffer: block,
			},
			Mode:    tpm2.TPMAlgCTR,
			Decrypt: decrypt,
			IV: tpm2.TPM2BIV{
				Buffer: iv,
			},
		}.Execute(rwr)
		if err != nil {
			return nil, err
		}
		block = r.OutData.Buffer
		iv = r.IV.Buffer
		out = append(out, block...)
	}
	return out, nil
}
