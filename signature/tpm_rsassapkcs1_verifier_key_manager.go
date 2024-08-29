package signature

import (
	"crypto/rsa"
	"errors"
	"fmt"
	"io"

	"github.com/salrashid123/tink-go-tpm/v2/common"
	tinktpmprotopb "github.com/salrashid123/tink-go-tpm/v2/proto"
	"github.com/tink-crypto/tink-go/v2/core/registry"
	"github.com/tink-crypto/tink-go/v2/keyset"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
	"google.golang.org/protobuf/proto"
)

const (
	rsaSSAPKCS1VerifierKeyVersion = 0
	rsaSSAPKCS1VerifierTypeURL    = "type.googleapis.com/github.salrashid123.tink-go-tpm.RsaSsaPkcs1PublicTpmKey"
)

var (
	errRSASSAPKCS1NotImplemented = errors.New("rsassapkcs1_verifier_key_manager: not implemented")
)

type tpmRSASSAPKCS1VerifierKeyManager struct {
	TpmDevice    io.ReadWriteCloser // TPM read closer
	AuthCallback common.AuthCallback
}

var _ registry.PrivateKeyManager = (*tpmRSASSAPKCS1SignerKeyManager)(nil)

func NewRSASSAPKCS1VerifierTpmKeyManager(rwr io.ReadWriteCloser, ac common.AuthCallback) *tpmRSASSAPKCS1VerifierKeyManager {
	return &tpmRSASSAPKCS1VerifierKeyManager{
		TpmDevice:    rwr,
		AuthCallback: ac,
	}
}

func (km *tpmRSASSAPKCS1VerifierKeyManager) UpdateAuthCallback(ac common.AuthCallback) {
	km.AuthCallback = ac
}

var _ registry.KeyManager = (*tpmRSASSAPKCS1VerifierKeyManager)(nil)

func (km *tpmRSASSAPKCS1VerifierKeyManager) Primitive(serializedKey []byte) (any, error) {
	if len(serializedKey) == 0 {
		return nil, fmt.Errorf("rsassapkcs1_verifier_key_manager: invalid serialized public key")
	}
	key := &tinktpmprotopb.RsaSsaPkcs1PublicTpmKey{}
	if err := proto.Unmarshal(serializedKey, key); err != nil {
		return nil, err
	}
	if err := validateRSAPKCS1PublicKey(key); err != nil {
		return nil, err
	}

	keyData := &rsa.PublicKey{
		E: int(bytesToBigInt(key.GetE()).Int64()),
		N: bytesToBigInt(key.GetN()),
	}
	return New_RSA_SSA_PKCS1_Verifier(hashName(key.GetParams().GetHashType()), *keyData)
}

func validateRSAPKCS1PublicKey(pubKey *tinktpmprotopb.RsaSsaPkcs1PublicTpmKey) error {
	if err := keyset.ValidateKeyVersion(pubKey.GetVersion(), rsaSSAPKCS1VerifierKeyVersion); err != nil {
		return err
	}
	return validateRSAPubKeyParams(
		pubKey.GetParams().GetHashType(),
		bytesToBigInt(pubKey.GetN()).BitLen(),
		pubKey.GetE())
}

func (km *tpmRSASSAPKCS1VerifierKeyManager) NewKey(serializedKeyFormat []byte) (proto.Message, error) {
	return nil, errRSASSAPKCS1NotImplemented
}

func (km *tpmRSASSAPKCS1VerifierKeyManager) NewKeyData(serializedKeyFormat []byte) (*tinkpb.KeyData, error) {
	return nil, errRSASSAPKCS1NotImplemented
}

func (km *tpmRSASSAPKCS1VerifierKeyManager) DoesSupport(typeURL string) bool {
	return typeURL == rsaSSAPKCS1VerifierTypeURL
}

func (km *tpmRSASSAPKCS1VerifierKeyManager) TypeURL() string {
	return rsaSSAPKCS1VerifierTypeURL
}
