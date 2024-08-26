package aead

import (
	"bytes"
	"context"
	"crypto/aes"
	"errors"
	"fmt"
	"io"

	keyfile "github.com/foxboron/go-tpm-keyfiles"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/tink-crypto/tink-go/v2/aead/subtle"
	"github.com/tink-crypto/tink-go/v2/core/registry"
	"github.com/tink-crypto/tink-go/v2/keyset"

	tpmctrsubtle "github.com/salrashid123/tink-go-tpm/v2/aead/subtle"
	"github.com/salrashid123/tink-go-tpm/v2/common"
	tpmmac "github.com/salrashid123/tink-go-tpm/v2/mac"
	tpmmacsubtle "github.com/salrashid123/tink-go-tpm/v2/mac/subtle"
	commonpb "github.com/tink-crypto/tink-go/v2/proto/common_go_proto"

	tinktpmprotopb "github.com/salrashid123/tink-go-tpm/v2/proto"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
	"google.golang.org/protobuf/proto"
)

const (
	aesHmacAEADKeyVersion = 0
	aesCtrKeyVersion      = 0
	aesHmacAEADTypeURL    = "type.googleapis.com/github.salrashid123.tink-go-tpm.AesCtrHmacAeadTpmKey"
	minHMACKeySizeInBytes = 16
	minTagSizeInBytes     = 10
)

var _ registry.KeyManager = (*aesCTRHMACAEADTPMKeyManager)(nil)

var errInvalidAesHMACAeadKey = errors.New("aes_hmac_aead_key_manager: invalid key")
var errInvalidAesHMACAeadKeyFormat = errors.New("aes_hmac_aead_key_manager: invalid key format")

func TpmAes128CtrHmacSha256Template() *tinkpb.KeyTemplate {
	return createTpmAesKeyTemplate(16, 32, tinktpmprotopb.HashType_SHA256, tinkpb.OutputPrefixType_TINK)
}

func TpmAes256CtrHmacSha256Template() *tinkpb.KeyTemplate {
	return createTpmAesKeyTemplate(32, 32, tinktpmprotopb.HashType_SHA256, tinkpb.OutputPrefixType_TINK)
}

func TpmAes128CtrHmacSha256NoPrefixTemplate() *tinkpb.KeyTemplate {
	return createTpmAesKeyTemplate(16, 32, tinktpmprotopb.HashType_SHA256, tinkpb.OutputPrefixType_RAW)
}

// createHMACKeyTemplate creates a new KeyTemplate for HMAC using the given parameters.
func createTpmAesKeyTemplate(keySize uint32, tagSize uint32, hashType tinktpmprotopb.HashType, opt tinkpb.OutputPrefixType) *tinkpb.KeyTemplate {

	format := tinktpmprotopb.AesCtrHmacAeadTpmKeyFormat{
		AesFormat: &tinktpmprotopb.AesCtrTpmKeyFormat{
			KeySize: keySize,
			IvSize:  aes.BlockSize,
		},
		HmacFormat: &tinktpmprotopb.HMACTpmKeyFormat{
			Params: &tinktpmprotopb.HMACParams{
				Hash:    hashType,
				TagSize: tagSize,
			},
			KeySize: 32, // this isn't even used but sha256 digest size is the key size (see tpm_hmac_key_manager.go createHMACTPMKeyTemplate() for explanation)
		},
	}
	serializedFormat, err := proto.Marshal(&format)
	if err != nil {
		fmt.Printf("failed to marshal key format: %s", err)
		return nil
	}

	return &tinkpb.KeyTemplate{
		TypeUrl:          aesHmacAEADTypeURL,
		Value:            serializedFormat,
		OutputPrefixType: opt,
	}
}

type aesCTRHMACAEADTPMKeyManager struct {
	TpmDevice    io.ReadWriteCloser // TPM read closer
	AuthCallback common.AuthCallback
}

func NewTpmAesHmacAeadKeyManager(rwr io.ReadWriteCloser, ac common.AuthCallback) *aesCTRHMACAEADTPMKeyManager {
	return &aesCTRHMACAEADTPMKeyManager{
		TpmDevice:    rwr,
		AuthCallback: ac,
	}
}

func (km *aesCTRHMACAEADTPMKeyManager) UpdateAuthCallback(ac common.AuthCallback) {
	km.AuthCallback = ac
}

// Primitive constructs a AesCtrHmacAEADTpmKey instance for the given serialized AesCtrHmacAEADTpmKey.
func (km *aesCTRHMACAEADTPMKeyManager) Primitive(serializedKey []byte) (interface{}, error) {

	if len(serializedKey) == 0 {
		return nil, errInvalidAesHMACAeadKey
	}
	tkey := new(tinktpmprotopb.TPMKey)
	if err := proto.Unmarshal(serializedKey, tkey); err != nil {
		return nil, errInvalidAesHMACAeadKey
	}

	if err := km.validateKey(tkey.GetAesCtrHmacAEADTpmKey()); err != nil {
		return nil, err
	}

	key := tkey.GetAesCtrHmacAEADTpmKey()

	// extract the aes-ctr key
	aesctrKey := key.GetAesCtrTpmkey()
	ctr, err := tpmctrsubtle.NewTPMAESCTR(context.Background(), &tpmctrsubtle.TpmAesCtr{
		TPMDevice:   km.TpmDevice,
		AuthSession: km.AuthCallback,
		KeyFormat:   *aesctrKey.GetKeyFormat(),
		Key:         *aesctrKey,
	})
	if err != nil {
		return nil, err
	}

	// extract the hmac key
	hmacKey := key.GetHmacTpmkey()
	hmac, err := tpmmacsubtle.NewTPMMAC(context.Background(), &tpmmacsubtle.TpmMAC{
		TPMDevice:   km.TpmDevice,
		Key:         *hmacKey,
		AuthSession: km.AuthCallback,
		KeyFormat:   *hmacKey.GetKeyFormat(),
	})
	if err != nil {
		return nil, err
	}

	// use both to create the aead primitive
	aead, err := subtle.NewEncryptThenAuthenticate(ctr, hmac, int(hmacKey.GetKeyFormat().GetParams().GetTagSize()))
	if err != nil {
		return nil, err
	}
	return aead, nil

}

// NewKey generates a new aesCTRHMACAEADTPMKeyManager according to specification in the given format.
func (km *aesCTRHMACAEADTPMKeyManager) NewKey(serializedKeyFormat []byte) (proto.Message, error) {

	if len(serializedKeyFormat) == 0 {
		return nil, errInvalidAesHMACAeadKey
	}
	keyFormat := new(tinktpmprotopb.AesCtrHmacAeadTpmKeyFormat)
	if err := proto.Unmarshal(serializedKeyFormat, keyFormat); err != nil {
		return nil, errInvalidAesHMACAeadKeyFormat
	}
	if err := km.validateKeyFormat(keyFormat); err != nil {
		return nil, err
	}

	// specify its parent directly
	rwr := transport.FromReadWriter(km.TpmDevice)

	primaryKey, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHOwner,
			Name:   tpm2.HandleName(tpm2.TPMRHOwner),
			Auth:   tpm2.PasswordAuth(km.AuthCallback.GetOwnerPassword()),
		},
		InPublic: tpm2.New2B(keyfile.ECCSRK_H2_Template),
	}.Execute(rwr)
	if err != nil {
		return nil, err
	}
	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: primaryKey.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(rwr)
	}()

	// create the hmac key
	var tpmHash tpm2.TPMAlgID
	switch h := keyFormat.HmacFormat.Params.Hash; h {
	case tinktpmprotopb.HashType_SHA256:
		tpmHash = tpm2.TPMAlgSHA256
	case tinktpmprotopb.HashType_SHA512:
		tpmHash = tpm2.TPMAlgSHA512
	default:
		tpmHash = tpm2.TPMAlgSHA256
	}

	hmacTemplate := tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgKeyedHash,
		NameAlg: tpmHash,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:            true,
			FixedParent:         true,
			SensitiveDataOrigin: true,
			UserWithAuth:        true,
			SignEncrypt:         true,
		},
		AuthPolicy: tpm2.TPM2BDigest{
			Buffer: km.AuthCallback.GetPolicyDigest(),
		},
		Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgKeyedHash,
			&tpm2.TPMSKeyedHashParms{
				Scheme: tpm2.TPMTKeyedHashScheme{
					Scheme: tpm2.TPMAlgHMAC,
					Details: tpm2.NewTPMUSchemeKeyedHash(tpm2.TPMAlgHMAC,
						&tpm2.TPMSSchemeHMAC{
							HashAlg: tpmHash,
						}),
				},
			}),
	}

	hmacKey, err := tpm2.CreateLoaded{
		ParentHandle: tpm2.AuthHandle{
			Handle: primaryKey.ObjectHandle,
			Name:   primaryKey.Name,
			Auth:   tpm2.PasswordAuth(nil),
		},
		InPublic: tpm2.New2BTemplate(&hmacTemplate),
		InSensitive: tpm2.TPM2BSensitiveCreate{
			Sensitive: &tpm2.TPMSSensitiveCreate{
				UserAuth: tpm2.TPM2BAuth{
					Buffer: km.AuthCallback.GetPassword(),
				},
			},
		},
	}.Execute(rwr)
	if err != nil {
		return nil, err
	}

	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: hmacKey.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(rwr)
	}()

	hasEmptyAuth := true
	if km.AuthCallback.GetPassword() != nil {
		hasEmptyAuth = false
	}

	hmacKeyFile := &keyfile.TPMKey{
		Keytype:   keyfile.OIDLoadableKey,
		Pubkey:    hmacKey.OutPublic,
		Privkey:   hmacKey.OutPrivate,
		EmptyAuth: hasEmptyAuth,
		Parent:    tpm2.TPMRHOwner,
	}
	hmacKeybytes := new(bytes.Buffer)
	err = keyfile.Encode(hmacKeybytes, hmacKeyFile)
	if err != nil {
		return nil, err
	}

	// create the aes-ctr key

	keysize := keyFormat.AesFormat.KeySize * 8

	aesTemplate := tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgSymCipher,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:            true,
			FixedParent:         true,
			UserWithAuth:        true,
			SensitiveDataOrigin: true,
			Decrypt:             true,
			SignEncrypt:         true,
		},
		AuthPolicy: tpm2.TPM2BDigest{
			Buffer: km.AuthCallback.GetPolicyDigest(),
		},
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgSymCipher,
			&tpm2.TPMSSymCipherParms{
				Sym: tpm2.TPMTSymDefObject{
					Algorithm: tpm2.TPMAlgAES,
					Mode:      tpm2.NewTPMUSymMode(tpm2.TPMAlgAES, tpm2.TPMAlgCTR),
					KeyBits: tpm2.NewTPMUSymKeyBits(
						tpm2.TPMAlgAES,
						tpm2.TPMKeyBits(keysize),
					),
				},
			},
		),
	}
	aesKey, err := tpm2.CreateLoaded{
		ParentHandle: tpm2.AuthHandle{
			Handle: primaryKey.ObjectHandle,
			Name:   primaryKey.Name,
			Auth:   tpm2.PasswordAuth(nil),
		},
		InPublic: tpm2.New2BTemplate(&aesTemplate),
		InSensitive: tpm2.TPM2BSensitiveCreate{
			Sensitive: &tpm2.TPMSSensitiveCreate{
				UserAuth: tpm2.TPM2BAuth{
					Buffer: km.AuthCallback.GetPassword(),
				},
			},
		},
	}.Execute(rwr)
	if err != nil {
		return nil, err
	}

	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: aesKey.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(rwr)
	}()

	aeskf := &keyfile.TPMKey{
		Keytype:   keyfile.OIDLoadableKey,
		Pubkey:    aesKey.OutPublic,
		Privkey:   aesKey.OutPrivate,
		Parent:    tpm2.TPMRHOwner,
		EmptyAuth: hasEmptyAuth,
	}
	aesKeyBytes := new(bytes.Buffer)
	err = keyfile.Encode(aesKeyBytes, aeskf)
	if err != nil {
		return nil, err
	}

	// embed both keys into the AesCtrHmacAeadTpmKey
	return &tinktpmprotopb.TPMKey{
		Version: common.TPMKeyVersion,
		KeyType: tinktpmprotopb.TPMKey_SYMMETRIC,
		Key: &tinktpmprotopb.TPMKey_AesCtrHmacAEADTpmKey{
			AesCtrHmacAEADTpmKey: &tinktpmprotopb.AesCtrHmacAeadTpmKey{
				Version: aesHmacAEADKeyVersion,
				HmacTpmkey: &tinktpmprotopb.HMACTpmKey{
					Version: tpmmac.HMACKeyVersion,
					KeyFormat: &tinktpmprotopb.HMACTpmKeyFormat{
						KeySize: keyFormat.HmacFormat.KeySize,
						Params: &tinktpmprotopb.HMACParams{
							Hash:    keyFormat.HmacFormat.Params.Hash,
							TagSize: keyFormat.HmacFormat.Params.TagSize,
						},
					},
					Keyfile:      hmacKeybytes.Bytes(),
					PolicyDigest: km.AuthCallback.GetPolicyDigest(),
				},
				AesCtrTpmkey: &tinktpmprotopb.AesCtrTpmKey{
					Version: aesCtrKeyVersion,
					KeyFormat: &tinktpmprotopb.AesCtrTpmKeyFormat{
						IvSize:  keyFormat.AesFormat.IvSize,
						KeySize: keyFormat.AesFormat.KeySize,
					},
					Keyfile:      aesKeyBytes.Bytes(),
					PolicyDigest: km.AuthCallback.GetPolicyDigest(),
				},
			},
		},
	}, nil
}

// NewKeyData generates a new KeyData according to specification in the given
// serialized HMACKeyFormat. This should be used solely by the key management API.
func (km *aesCTRHMACAEADTPMKeyManager) NewKeyData(serializedKeyFormat []byte) (*tinkpb.KeyData, error) {
	key, err := km.NewKey(serializedKeyFormat)
	if err != nil {
		return nil, err
	}
	serializedKey, err := proto.Marshal(key)
	if err != nil {
		return nil, fmt.Errorf("error marshalling  key %v", err)
	}

	return &tinkpb.KeyData{
		TypeUrl:         aesHmacAEADTypeURL,
		Value:           serializedKey,
		KeyMaterialType: km.KeyMaterialType(),
	}, nil
}

// DoesSupport checks whether this KeyManager supports the given key type.
func (km *aesCTRHMACAEADTPMKeyManager) DoesSupport(typeURL string) bool {
	return typeURL == aesHmacAEADTypeURL
}

// TypeURL returns the type URL of keys managed by this KeyManager.
func (km *aesCTRHMACAEADTPMKeyManager) TypeURL() string {
	return aesHmacAEADTypeURL
}

// KeyMaterialType returns the key material type of this key manager.
func (km *aesCTRHMACAEADTPMKeyManager) KeyMaterialType() tinkpb.KeyData_KeyMaterialType {
	return tinkpb.KeyData_SYMMETRIC
}

// validateKey validates the given AesCtrHmacAeadKey proto.
func (km *aesCTRHMACAEADTPMKeyManager) validateKey(key *tinktpmprotopb.AesCtrHmacAeadTpmKey) error {
	if err := keyset.ValidateKeyVersion(key.GetVersion(), aesHmacAEADKeyVersion); err != nil {
		return fmt.Errorf("aes_ctr_hmac_aead_key_manager: %v", err)
	}
	if err := keyset.ValidateKeyVersion(key.GetAesCtrTpmkey().GetVersion(), aesCtrKeyVersion); err != nil {
		return fmt.Errorf("aes_ctr_hmac_aead_key_manager: %v", err)
	}
	if err := keyset.ValidateKeyVersion(key.GetHmacTpmkey().GetVersion(), tpmmac.HMACKeyVersion); err != nil {
		return fmt.Errorf("aes_ctr_hmac_aead_key_manager: %v", err)
	}
	// // Validate AesCtrKey.
	keySize := key.GetAesCtrTpmkey().GetKeyFormat().GetKeySize()
	if err := subtle.ValidateAESKeySize(keySize); err != nil {
		return fmt.Errorf("aes_ctr_hmac_aead_key_manager: %v", err)
	}
	ivs := key.GetAesCtrTpmkey().GetKeyFormat().GetIvSize()
	if ivs < subtle.AESCTRMinIVSize || ivs > 16 {
		return errors.New("aes_ctr_hmac_aead_key_manager: invalid AesCtrHmacAeadKey: IV size out of range")
	}
	return nil
}

// validateKeyFormat validates the given AesCtrHmacAeadKeyFormat proto.
func (km *aesCTRHMACAEADTPMKeyManager) validateKeyFormat(format *tinktpmprotopb.AesCtrHmacAeadTpmKeyFormat) error {
	// Validate AesCtrKeyFormat.

	if err := subtle.ValidateAESKeySize(format.GetAesFormat().GetKeySize()); err != nil {
		return fmt.Errorf("aes_ctr_hmac_aead_key_manager: %s", err)
	}

	if format.GetAesFormat().GetIvSize() < subtle.AESCTRMinIVSize || format.GetAesFormat().GetIvSize() > 16 {
		return errors.New("aes_ctr_hmac_aead_key_manager: invalid AesCtrHmacAeadKeyFormat: IV size out of range")
	}

	// Validate HmacKeyFormat.
	hmacKeyFormat := format.GetHmacFormat()
	if hmacKeyFormat.GetKeySize() < minHMACKeySizeInBytes {
		return errors.New("aes_ctr_hmac_aead_key_manager: HMAC KeySize is too small")
	}
	if hmacKeyFormat.GetParams().GetTagSize() < minTagSizeInBytes {
		return fmt.Errorf("aes_ctr_hmac_aead_key_manager: invalid HmacParams: TagSize %d is too small", hmacKeyFormat.GetParams().GetTagSize())
	}

	maxTagSizes := map[commonpb.HashType]uint32{
		commonpb.HashType_SHA1:   20,
		commonpb.HashType_SHA224: 28,
		commonpb.HashType_SHA256: 32,
		commonpb.HashType_SHA384: 48,
		commonpb.HashType_SHA512: 64}

	maxTagSize, ok := maxTagSizes[commonpb.HashType(hmacKeyFormat.GetParams().Hash)]
	if !ok {
		return fmt.Errorf("aes_ctr_hmac_aead_key_manager: invalid HmacParams: HashType %q not supported",
			hmacKeyFormat.GetParams().GetHash())
	}
	if hmacKeyFormat.GetParams().GetTagSize() > maxTagSize {
		return fmt.Errorf("aes_ctr_hmac_aead_key_manager: invalid HmacParams: tagSize %d is too big for HashType %q",
			hmacKeyFormat.GetParams().GetTagSize(), hmacKeyFormat.GetParams().GetHash())
	}
	return nil
}
