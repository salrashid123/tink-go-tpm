package subtle

import (
	"bytes"
	"context"
	"crypto/hmac"
	"encoding/hex"
	"errors"
	"fmt"
	"io"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	tinkcommon "github.com/salrashid123/tink-go-tpm/v2/common"
	tinktpmprotopb "github.com/salrashid123/tink-go-tpm/v2/proto"
	"github.com/tink-crypto/tink-go/v2/tink"
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
	Key         tinktpmprotopb.HMACKey
	AuthSession tinkcommon.AuthCallback
	KeyFormat   tinktpmprotopb.HMACKeyFormat
	objAuth     tpm2.TPM2BAuth
	ctx         context.Context
	rwr         transport.TPM
}

var _ tink.MAC = (*TpmMAC)(nil)

func NewTPMMAC(ctx context.Context, conf *TpmMAC) (*TpmMAC, error) {

	conf.ctx = ctx
	conf.rwr = transport.FromReadWriter(conf.TPMDevice)

	if !bytes.Equal(conf.Key.PolicyDigest, conf.AuthSession.GetPolicyDigest()) {
		return nil, fmt.Errorf("error creating key: policy digest mismatch in key %s, in session: %s", hex.EncodeToString(conf.Key.PolicyDigest), hex.EncodeToString(conf.AuthSession.GetPolicyDigest()))
	}

	conf.objAuth = tpm2.TPM2BAuth{}
	return conf, nil
}

func (a *TpmMAC) ComputeMAC(data []byte) ([]byte, error) {
	m, err := a.hmac(a.rwr, data)
	if err != nil {
		// directly print the error here: go-tpm core library does not print the inner error
		fmt.Printf("tink_tpm mac error: %v\n", err)
		return nil, err
	}
	return m, nil
}

func (a *TpmMAC) VerifyMAC(mac []byte, data []byte) error {
	expectedMAC, err := a.ComputeMAC(data)
	if err != nil {
		fmt.Printf("tink_tpm mac error: %v\n", err)
		return err
	}
	if hmac.Equal(expectedMAC, mac) {
		return nil
	}
	return errors.New("HMAC: invalid MAC")
}

func (a *TpmMAC) hmac(rwr transport.TPM, data []byte) ([]byte, error) {

	primaryKey, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHEndorsement,
		InPublic:      tpm2.New2B(tinkcommon.ECCSRKH2Template),
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
		ParentHandle: tpm2.NamedHandle{
			Handle: primaryKey.ObjectHandle,
			Name:   primaryKey.Name,
		},
		InPrivate: tpm2.TPM2BPrivate{
			Buffer: a.Key.Private,
		},
		InPublic: tpm2.BytesAs2B[tpm2.TPMTPublic](a.Key.Public),
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
