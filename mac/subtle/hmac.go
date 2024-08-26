package subtle

import (
	"bytes"
	"context"
	"crypto/hmac"
	"encoding/hex"
	"errors"
	"fmt"
	"io"

	keyfile "github.com/foxboron/go-tpm-keyfiles"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	tinkcommon "github.com/salrashid123/tink-go-tpm/v2/common"
	tinktpmprotopb "github.com/salrashid123/tink-go-tpm/v2/proto"
	"github.com/tink-crypto/tink-go/tink"
)

const (
	// Minimum key size in bytes.
	minKeySizeInBytes = uint32(16)

	// Minimum tag size in bytes. This provides minimum 80-bit security strength.
	minTagSizeInBytes = uint32(10)

	maxInputBuffer = 1024
)

type TpmMAC struct {
	tink.MAC
	TPMDevice   io.ReadWriteCloser
	Key         tinktpmprotopb.HMACTpmKey
	AuthSession tinkcommon.AuthCallback
	KeyFormat   tinktpmprotopb.HMACTpmKeyFormat
	objAuth     tpm2.TPM2BAuth
	ctx         context.Context
	rwr         transport.TPM
	kf          *keyfile.TPMKey
}

var _ tink.MAC = (*TpmMAC)(nil)

func NewTPMMAC(ctx context.Context, conf *TpmMAC) (*TpmMAC, error) {

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

	conf.objAuth = tpm2.TPM2BAuth{}
	return conf, nil
}

func (a *TpmMAC) ComputeMAC(data []byte) ([]byte, error) {
	m, err := a.hmac(a.rwr, data)
	if err != nil {
		return nil, err
	}
	return m, nil
}

func (a *TpmMAC) VerifyMAC(mac []byte, data []byte) error {
	expectedMAC, err := a.ComputeMAC(data)
	if err != nil {
		// printing the root error here since this error details are not propagated back
		//   https://github.com/tink-crypto/tink-go/blob/main/aead/aead_factory.go#L163
		//   https://github.com/tink-crypto/tink-go/blob/main/aead/subtle/encrypt_then_authenticate.go#L108
		fmt.Printf("Error computing mac: %v\n", err)
		return err
	}
	if hmac.Equal(expectedMAC, mac) {
		return nil
	}
	//fmt.Printf("hmac: invalid MAC\n")
	return errors.New("HMAC: invalid MAC")
}

func (a *TpmMAC) hmac(rwr transport.TPM, data []byte) ([]byte, error) {

	primaryKey, err := tpm2.CreatePrimary{
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
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: primaryKey.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(a.rwr)
	}()

	loadRsp, err := tpm2.Load{
		ParentHandle: tpm2.AuthHandle{
			Handle: primaryKey.ObjectHandle,
			Name:   primaryKey.Name,
			Auth:   tpm2.PasswordAuth(nil),
		},
		InPrivate: tpm2.TPM2BPrivate{
			Buffer: a.kf.Privkey.Buffer,
		},
		InPublic: tpm2.BytesAs2B[tpm2.TPMTPublic](a.kf.Pubkey.Bytes()),
	}.Execute(a.rwr)
	if err != nil {
		return nil, err
	}

	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: loadRsp.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(a.rwr)
	}()

	se, closer, err := a.AuthSession.GetSession()
	if err != nil {
		return nil, err
	}
	defer closer()
	hmacStart := tpm2.HmacStart{
		Handle: tpm2.AuthHandle{
			Handle: loadRsp.ObjectHandle,
			Name:   loadRsp.Name,
			Auth:   se,
		},
		Auth:    a.objAuth,
		HashAlg: tpm2.TPMAlgNull,
	}

	rspHS, err := hmacStart.Execute(rwr)
	if err != nil {
		return nil, err
	}

	authHandle := tpm2.AuthHandle{
		Name:   loadRsp.Name,
		Handle: rspHS.SequenceHandle,
		Auth:   tpm2.PasswordAuth(a.objAuth.Buffer),
	}
	for len(data) > maxInputBuffer {
		sequenceUpdate := tpm2.SequenceUpdate{
			SequenceHandle: authHandle,
			Buffer: tpm2.TPM2BMaxBuffer{
				Buffer: data[:maxInputBuffer],
			},
		}
		_, err = sequenceUpdate.Execute(rwr)
		if err != nil {
			return nil, err
		}
		data = data[maxInputBuffer:]
	}

	sequenceComplete := tpm2.SequenceComplete{
		SequenceHandle: authHandle,
		Buffer: tpm2.TPM2BMaxBuffer{
			Buffer: data,
		},
		Hierarchy: tpm2.TPMRHOwner,
	}

	rspSC, err := sequenceComplete.Execute(rwr)
	if err != nil {
		return nil, err
	}

	return rspSC.Result.Buffer, nil

}
