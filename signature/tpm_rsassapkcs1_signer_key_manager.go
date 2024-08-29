package signature

import (
	"bytes"
	"errors"
	"io"
	"math/big"

	keyfile "github.com/foxboron/go-tpm-keyfiles"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/salrashid123/tink-go-tpm/v2/common"
	tinktpmprotopb "github.com/salrashid123/tink-go-tpm/v2/proto"
	"github.com/tink-crypto/tink-go/v2/core/registry"
	"github.com/tink-crypto/tink-go/v2/keyset"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
	"google.golang.org/protobuf/proto"
)

const (
	rsaSSAPKCS1SignerKeyVersion = 0
	rsaSSAPKCS1SignerTypeURL    = "type.googleapis.com/github.salrashid123.tink-go-tpm.RsaSsaPkcs1PrivateTpmKey"
)

var (
	errInvalidRSASSAPKCS1SignKey       = errors.New("rsassapkcs1_signer_key_manager: invalid key")
	errInvalidRSASSAPKCS1SignKeyFormat = errors.New("rsassapkcs1_signer_key_manager: invalid key format")
)

type tpmRSASSAPKCS1SignerKeyManager struct {
	TpmDevice    io.ReadWriteCloser // TPM read closer
	AuthCallback common.AuthCallback
}

var _ registry.PrivateKeyManager = (*tpmRSASSAPKCS1SignerKeyManager)(nil)

func NewRSASSAPKCS1SignerTpmKeyManager(rwr io.ReadWriteCloser, ac common.AuthCallback) *tpmRSASSAPKCS1SignerKeyManager {
	return &tpmRSASSAPKCS1SignerKeyManager{
		TpmDevice:    rwr,
		AuthCallback: ac,
	}
}

func (km *tpmRSASSAPKCS1SignerKeyManager) UpdateAuthCallback(ac common.AuthCallback) {
	km.AuthCallback = ac
}

func (km *tpmRSASSAPKCS1SignerKeyManager) Primitive(serializedKey []byte) (any, error) {
	if false {
		return nil, errInvalidRSASSAPKCS1SignKey
	}
	key := &tinktpmprotopb.RsaSsaPkcs1PrivateTpmKey{}
	if err := proto.Unmarshal(serializedKey, key); err != nil {
		return nil, err
	}
	if err := validateRSAPKCS1PrivateKey(key); err != nil {
		return nil, err
	}

	kf, err := keyfile.Decode(key.Keyfile)
	if err != nil {
		return nil, err
	}

	h := hashName(key.GetPublicKey().GetParams().GetHashType())
	if err := Validate_RSA_SSA_PKCS1(*km, h, *kf); err != nil {
		return nil, err
	}
	return New_RSA_SSA_PKCS1_Signer(*km, h, *kf)
}

func validateRSAPKCS1PrivateKey(privKey *tinktpmprotopb.RsaSsaPkcs1PrivateTpmKey) error {
	if err := keyset.ValidateKeyVersion(privKey.GetVersion(), rsaSSAPKCS1SignerKeyVersion); err != nil {
		return err
	}
	return validateRSAPKCS1PublicKey(privKey.GetPublicKey())
}

func (km *tpmRSASSAPKCS1SignerKeyManager) NewKey(serializedKeyFormat []byte) (proto.Message, error) {
	if len(serializedKeyFormat) == 0 {
		return nil, errInvalidRSASSAPKCS1SignKeyFormat
	}
	keyFormat := &tinktpmprotopb.RsaSsaPkcs1KeyTpmFormat{}
	if err := proto.Unmarshal(serializedKeyFormat, keyFormat); err != nil {
		return nil, err
	}
	if err := validateRSAPubKeyParams(
		keyFormat.GetParams().GetHashType(),
		int(keyFormat.GetModulusSizeInBits()),
		keyFormat.GetPublicExponent()); err != nil {
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

	var tpmHash tpm2.TPMAlgID
	switch h := keyFormat.Params.HashType; h {
	case tinktpmprotopb.HashType_SHA256:
		tpmHash = tpm2.TPMAlgSHA256
	case tinktpmprotopb.HashType_SHA512:
		tpmHash = tpm2.TPMAlgSHA512
	default:
		tpmHash = tpm2.TPMAlgSHA256
	}

	e := bytesToBigInt(keyFormat.PublicExponent)
	if !e.IsInt64() {
		return nil, err
	}

	rsaTemplate := tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgRSA,
		NameAlg: tpm2.TPMAlgSHA256,
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
		Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgRSA,
			&tpm2.TPMSRSAParms{
				Scheme: tpm2.TPMTRSAScheme{
					Scheme: tpm2.TPMAlgRSASSA,
					Details: tpm2.NewTPMUAsymScheme(
						tpm2.TPMAlgRSASSA,
						&tpm2.TPMSSigSchemeRSASSA{
							HashAlg: tpmHash,
						},
					),
				},
				KeyBits:  tpm2.TPMKeyBits(keyFormat.GetModulusSizeInBits()),
				Exponent: uint32(e.Uint64()),
			},
		),
	}

	rsaKey, err := tpm2.CreateLoaded{
		ParentHandle: tpm2.AuthHandle{
			Handle: primaryKey.ObjectHandle,
			Name:   primaryKey.Name,
			Auth:   tpm2.PasswordAuth(nil),
		},
		InPublic: tpm2.New2BTemplate(&rsaTemplate),
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
			FlushHandle: rsaKey.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(rwr)
	}()

	hasEmptyAuth := true
	if km.AuthCallback.GetPassword() != nil {
		hasEmptyAuth = false
	}

	rsaKeyFile := &keyfile.TPMKey{
		Keytype:   keyfile.OIDLoadableKey,
		Pubkey:    rsaKey.OutPublic,
		Privkey:   rsaKey.OutPrivate,
		EmptyAuth: hasEmptyAuth,
		Parent:    tpm2.TPMRHOwner,
	}
	rsaKeybytes := new(bytes.Buffer)
	err = keyfile.Encode(rsaKeybytes, rsaKeyFile)
	if err != nil {
		return nil, err
	}

	outPub, err := rsaKey.OutPublic.Contents()
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

	// *****************

	// rsaKey, err := rsa.GenerateKey(rand.Reader, int(keyFormat.GetModulusSizeInBits()))
	// if err != nil {
	// 	return nil, fmt.Errorf("generating RSA key: %s", err)
	// }
	pubKey := &tinktpmprotopb.RsaSsaPkcs1PublicTpmKey{
		Version: rsaSSAPKCS1SignerKeyVersion,
		Params: &tinktpmprotopb.RsaSsaPkcs1Params{
			HashType: keyFormat.GetParams().GetHashType(),
		},
		N: rsaPub.N.Bytes(),
		E: big.NewInt(int64(rsaPub.E)).Bytes(),
	}
	return &tinktpmprotopb.RsaSsaPkcs1PrivateTpmKey{
		Version:   rsaSSAPKCS1SignerKeyVersion,
		PublicKey: pubKey,
		Keyfile:   rsaKeybytes.Bytes(),
		// D:         rsaKey.D.Bytes(),
		// P:         rsaKey.Primes[0].Bytes(),
		// Q:         rsaKey.Primes[1].Bytes(),
		// Dp:        rsaKey.Precomputed.Dp.Bytes(),
		// Dq:        rsaKey.Precomputed.Dq.Bytes(),
		// In crypto/rsa `Qinv` is the "Chinese Remainder Theorem
		// coefficient q^(-1) mod p". This corresponds with `Crt` in
		// the Tink proto. This is unrelated to `CRTValues`, which
		// contains values specifically for additional primes, which
		// are not supported by Tink.
		//Crt: rsaKey.Precomputed.Qinv.Bytes(),
	}, nil
}

func (km *tpmRSASSAPKCS1SignerKeyManager) NewKeyData(serializedKeyFormat []byte) (*tinkpb.KeyData, error) {
	key, err := km.NewKey(serializedKeyFormat)
	if err != nil {
		return nil, err
	}
	serializedKey, err := proto.Marshal(key)
	if err != nil {
		return nil, errInvalidRSASSAPKCS1SignKeyFormat
	}
	return &tinkpb.KeyData{
		TypeUrl:         rsaSSAPKCS1SignerTypeURL,
		Value:           serializedKey,
		KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PRIVATE,
	}, nil
}

// PublicKeyData extracts the public key data from the private key.
func (km *tpmRSASSAPKCS1SignerKeyManager) PublicKeyData(serializedPrivKey []byte) (*tinkpb.KeyData, error) {
	privKey := &tinktpmprotopb.RsaSsaPkcs1PrivateTpmKey{}
	if err := proto.Unmarshal(serializedPrivKey, privKey); err != nil {
		return nil, err
	}
	if err := validateRSAPKCS1PrivateKey(privKey); err != nil {
		return nil, err
	}
	serializedPubKey, err := proto.Marshal(privKey.GetPublicKey())
	if err != nil {
		return nil, err
	}
	return &tinkpb.KeyData{
		TypeUrl:         rsaSSAPKCS1VerifierTypeURL,
		Value:           serializedPubKey,
		KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
	}, nil
}

// DoesSupport indicates if this key manager supports the given key type.
func (km *tpmRSASSAPKCS1SignerKeyManager) DoesSupport(typeURL string) bool {
	return typeURL == rsaSSAPKCS1SignerTypeURL
}

// TypeURL returns the key type of keys managed by this key manager.
func (km *tpmRSASSAPKCS1SignerKeyManager) TypeURL() string {
	return rsaSSAPKCS1SignerTypeURL
}
