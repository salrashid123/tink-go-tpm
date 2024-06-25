package tinktpm

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	tpmsubtle "github.com/salrashid123/tink-go-tpm/v2/mac/subtle"
	"github.com/tink-crypto/tink-go/v2/core/registry"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/mac/subtle"

	tinkcommon "github.com/salrashid123/tink-go-tpm/v2/common"
	tinktpmprotopb "github.com/salrashid123/tink-go-tpm/v2/proto"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
	"google.golang.org/protobuf/proto"
)

/*
To compile the proto:

go get -u github.com/golang/protobuf/protoc-gen-go

# to compile the protobuf with libprotoc 25.1
/usr/local/bin/protoc -I ./ --include_imports \
   --experimental_allow_proto3_optional --include_source_info \
   --descriptor_set_out=proto/tinktpm.proto.pb --go_out=paths=source_relative:. proto/tinktpm.proto
*/

const (
	hmacKeyVersion = 0
	//hmacTypeURL    = "type.googleapis.com/google.crypto.tink.TPMHmacKey"
	hmacTypeURL = "type.googleapis.com/github.salrashid123.tink-go-tpm.TPMHmacKey"
)

var _ registry.KeyManager = (*TPMHMACKeyManager)(nil)

var errInvalidHMACKey = errors.New("hmac_key_manager: invalid key")
var errInvalidHMACKeyFormat = errors.New("hmac_key_manager: invalid key format")

func HMACSHA256Tag256KeyTPMTemplate() *tinkpb.KeyTemplate {
	return createHMACTPMKeyTemplate(32, 32, tinktpmprotopb.HashType_SHA256, tinkpb.OutputPrefixType_TINK)
}

func HMACSHA256Tag256KeyTPMNoPrefixTemplate() *tinkpb.KeyTemplate {
	return createHMACTPMKeyTemplate(32, 32, tinktpmprotopb.HashType_SHA256, tinkpb.OutputPrefixType_RAW)
}

func HMACSHA512Tag256KeyTPMTemplate() *tinkpb.KeyTemplate {
	return createHMACTPMKeyTemplate(64, 32, tinktpmprotopb.HashType_SHA512, tinkpb.OutputPrefixType_TINK)
}

func HMACSHA512Tag256KeyTPMNoPrefixTemplate() *tinkpb.KeyTemplate {
	return createHMACTPMKeyTemplate(64, 32, tinktpmprotopb.HashType_SHA512, tinkpb.OutputPrefixType_TINK)
}

// createHMACKeyTemplate creates a new KeyTemplate for HMAC using the given parameters.
func createHMACTPMKeyTemplate(keySize, tagSize uint32, hashType tinktpmprotopb.HashType, opt tinkpb.OutputPrefixType) *tinkpb.KeyTemplate {
	params := tinktpmprotopb.HMACParams{
		Hash:    hashType,
		TagSize: tagSize,
	}
	format := tinktpmprotopb.HMACKeyFormat{
		Params:  &params,
		KeySize: keySize,
	}
	serializedFormat, err := proto.Marshal(&format)
	if err != nil {
		fmt.Errorf("failed to marshal key format: %s", err)
	}

	return &tinkpb.KeyTemplate{
		TypeUrl:          hmacTypeURL,
		Value:            serializedFormat,
		OutputPrefixType: opt,
	}
}

// hmacKeyManager generates new HMAC keys and produces new instances of HMAC.
type TPMHMACKeyManager struct {
	TpmDevice    io.ReadWriteCloser // TPM read closer
	AuthCallback tinkcommon.AuthCallback
}

func NewTPMHMACKeyManager(rwr io.ReadWriteCloser, ac tinkcommon.AuthCallback) *TPMHMACKeyManager {
	return &TPMHMACKeyManager{
		TpmDevice:    rwr,
		AuthCallback: ac,
	}
}

// Primitive constructs a HMAC instance for the given serialized HMACKey.
func (km *TPMHMACKeyManager) Primitive(serializedKey []byte) (interface{}, error) {

	if len(serializedKey) == 0 {
		return nil, errInvalidHMACKey
	}
	tkey := new(tinktpmprotopb.TPMKey)
	if err := proto.Unmarshal(serializedKey, tkey); err != nil {
		return nil, errInvalidHMACKey
	}
	key := tkey.GetHmacKey()
	if err := km.validateKey(key); err != nil {
		return nil, err
	}

	hmac, err := tpmsubtle.NewTPMMAC(context.Background(), &tpmsubtle.TpmMAC{
		TPMDevice:   km.TpmDevice,
		Key:         *tkey.GetHmacKey(),
		AuthSession: km.AuthCallback,
		KeyFormat:   *key.KeyFormat,
	})
	if err != nil {
		return nil, err
	}
	return hmac, nil
}

// NewKey generates a new HMACKey according to specification in the given HMACKeyFormat.
func (km *TPMHMACKeyManager) NewKey(serializedKeyFormat []byte) (proto.Message, error) {

	if len(serializedKeyFormat) == 0 {
		return nil, errInvalidHMACKeyFormat
	}
	keyFormat := new(tinktpmprotopb.HMACKeyFormat)
	if err := proto.Unmarshal(serializedKeyFormat, keyFormat); err != nil {
		return nil, errInvalidHMACKeyFormat
	}
	if err := km.validateKeyFormat(keyFormat); err != nil {
		return nil, fmt.Errorf("hmac_key_manager: invalid key format: %s", err)
	}

	// specify its parent directly
	rwr := transport.FromReadWriter(km.TpmDevice)

	primaryKey, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHEndorsement,
		InPublic:      tpm2.New2B(tinkcommon.ECCSRKH2Template),
	}.Execute(rwr)
	if err != nil {
		return nil, fmt.Errorf("hmac_key_manager: error creating primary: %s", err)
	}
	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: primaryKey.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(rwr)
	}()

	var tpmHash tpm2.TPMAlgID
	switch h := keyFormat.Params.Hash; h {
	case tinktpmprotopb.HashType_SHA256:
		tpmHash = tpm2.TPMAlgSHA256
	case tinktpmprotopb.HashType_SHA512:
		tpmHash = tpm2.TPMAlgSHA512
	default:
		tpmHash = tpm2.TPMAlgSHA256
	}

	sdo := true
	if km.AuthCallback.GetSensitive() != nil {
		sdo = false
	}
	hmacTemplate := tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgKeyedHash,
		NameAlg: tpmHash,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:            true,
			FixedParent:         true,
			SensitiveDataOrigin: sdo,
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
				Data: tpm2.NewTPMUSensitiveCreate(&tpm2.TPM2BSensitiveData{
					Buffer: km.AuthCallback.GetSensitive(),
				}),
			},
		},
	}.Execute(rwr)
	if err != nil {
		return nil, fmt.Errorf("hmac_key_manager: error creating hmac key: %s", err)
	}

	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: hmacKey.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(rwr)
	}()

	return &tinktpmprotopb.TPMKey{
		Version: hmacKeyVersion,
		KeyType: tinktpmprotopb.TPMKey_HMAC,
		Key: &tinktpmprotopb.TPMKey_HmacKey{
			HmacKey: &tinktpmprotopb.HMACKey{
				KeyFormat: &tinktpmprotopb.HMACKeyFormat{
					Version: hmacKeyVersion,
					KeySize: keyFormat.KeySize,
					Params: &tinktpmprotopb.HMACParams{
						Hash:    keyFormat.Params.Hash,
						TagSize: keyFormat.Params.TagSize,
					},
				},
				Private:      hmacKey.OutPrivate.Buffer,
				Public:       hmacKey.OutPublic.Bytes(),
				PolicyDigest: km.AuthCallback.GetPolicyDigest(),
			},
		},
	}, nil
}

// NewKeyData generates a new KeyData according to specification in the given
// serialized HMACKeyFormat. This should be used solely by the key management API.
func (km *TPMHMACKeyManager) NewKeyData(serializedKeyFormat []byte) (*tinkpb.KeyData, error) {
	key, err := km.NewKey(serializedKeyFormat)
	if err != nil {
		return nil, err
	}
	serializedKey, err := proto.Marshal(key)
	if err != nil {
		return nil, errInvalidHMACKeyFormat
	}

	return &tinkpb.KeyData{
		TypeUrl:         hmacTypeURL,
		Value:           serializedKey,
		KeyMaterialType: km.KeyMaterialType(),
	}, nil
}

// DoesSupport checks whether this KeyManager supports the given key type.
func (km *TPMHMACKeyManager) DoesSupport(typeURL string) bool {
	return typeURL == hmacTypeURL
}

// TypeURL returns the type URL of keys managed by this KeyManager.
func (km *TPMHMACKeyManager) TypeURL() string {
	return hmacTypeURL
}

// KeyMaterialType returns the key material type of this key manager.
func (km *TPMHMACKeyManager) KeyMaterialType() tinkpb.KeyData_KeyMaterialType {
	return tinkpb.KeyData_SYMMETRIC
}

// // DeriveKey derives a new key from serializedKeyFormat and pseudorandomness.
func (km *TPMHMACKeyManager) DeriveKey(serializedKeyFormat []byte, pseudorandomness io.Reader) (proto.Message, error) {
	if len(serializedKeyFormat) == 0 {
		return nil, errInvalidHMACKeyFormat
	}

	keyFormat := new(tinktpmprotopb.HMACKeyFormat)
	if err := proto.Unmarshal(serializedKeyFormat, keyFormat); err != nil {
		return nil, errInvalidHMACKeyFormat
	}
	if err := km.validateKeyFormat(keyFormat); err != nil {
		return nil, fmt.Errorf("hmac_key_manager: invalid key format: %s", err)
	}

	if err := keyset.ValidateKeyVersion(keyFormat.GetVersion(), hmacKeyVersion); err != nil {
		return nil, fmt.Errorf("hmac_key_manager: invalid key version: %s", err)
	}

	return km.NewKey(serializedKeyFormat)
}

// validateKey validates the given HMACKey. It only validates the version of the
// key because other parameters will be validated in primitive construction.
func (km *TPMHMACKeyManager) validateKey(key *tinktpmprotopb.HMACKey) error {
	err := keyset.ValidateKeyVersion(key.KeyFormat.Version, hmacKeyVersion)
	if err != nil {
		return fmt.Errorf("hmac_key_manager: invalid version: %s", err)
	}
	hash := tinktpmprotopb.HashType_name[int32(key.KeyFormat.GetParams().GetHash())]
	return subtle.ValidateHMACParams(hash, key.KeyFormat.KeySize, key.KeyFormat.GetParams().GetTagSize())
}

// validateKeyFormat validates the given HMACKeyFormat
func (km *TPMHMACKeyManager) validateKeyFormat(format *tinktpmprotopb.HMACKeyFormat) error {
	hash := tinktpmprotopb.HashType_name[int32(format.GetParams().GetHash())]
	return subtle.ValidateHMACParams(hash, format.KeySize, format.GetParams().GetTagSize())
}
