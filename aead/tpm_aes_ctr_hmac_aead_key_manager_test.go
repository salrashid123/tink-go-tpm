package aead

import (
	"testing"

	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/stretchr/testify/require"

	tinkcommon "github.com/salrashid123/tink-go-tpm/v2/common"
	"github.com/tink-crypto/tink-go/v2/aead"
	"github.com/tink-crypto/tink-go/v2/core/registry"
	"github.com/tink-crypto/tink-go/v2/keyset"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
)

func TestAead(t *testing.T) {
	tpmDevice, err := simulator.Get()
	require.NoError(t, err)
	defer tpmDevice.Close()

	plaintext := "foo"

	rwr := transport.FromReadWriter(tpmDevice)

	sess, cleanup1, err := tpm2.PolicySession(rwr, tpm2.TPMAlgSHA256, 16, tpm2.Trial())
	require.NoError(t, err)
	defer cleanup1()

	pav := tpm2.PolicyAuthValue{
		PolicySession: sess.Handle(),
	}
	_, err = pav.Execute(rwr)
	require.NoError(t, err)

	pgd, err := tpm2.PolicyGetDigest{
		PolicySession: sess.Handle(),
	}.Execute(rwr)
	require.NoError(t, err)

	se, err := tinkcommon.NewPasswordSession(rwr, nil, nil, pgd.PolicyDigest.Buffer)
	require.NoError(t, err)

	aesKeyManager := NewTpmAesHmacAeadKeyManager(tpmDevice, se)
	err = registry.RegisterKeyManager(aesKeyManager)
	require.NoError(t, err)

	tests := []struct {
		name     string
		template *tinkpb.KeyTemplate
	}{
		{"TpmAes128CtrHmacSha256Template", TpmAes128CtrHmacSha256Template()},
		{"TpmAes128CtrHmacSha256NoPrefixTemplate", TpmAes128CtrHmacSha256NoPrefixTemplate()},
		{"TpmAes256CtrHmacSha256Template", TpmAes256CtrHmacSha256Template()},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {

			kh1, err := keyset.NewHandle(tc.template)
			require.NoError(t, err)

			a, err := aead.New(kh1)
			require.NoError(t, err)

			e, err := a.Encrypt([]byte(plaintext), nil)
			require.NoError(t, err)

			d, err := a.Decrypt(e, nil)
			require.NoError(t, err)

			require.Equal(t, d, []byte(plaintext))
		})
	}
}

func TestAeadFail(t *testing.T) {
	tpmDevice, err := simulator.Get()
	require.NoError(t, err)
	defer tpmDevice.Close()

	plaintext := "foo"

	rwr := transport.FromReadWriter(tpmDevice)

	sess, cleanup1, err := tpm2.PolicySession(rwr, tpm2.TPMAlgSHA256, 16, tpm2.Trial())
	require.NoError(t, err)
	defer cleanup1()

	pav := tpm2.PolicyAuthValue{
		PolicySession: sess.Handle(),
	}
	_, err = pav.Execute(rwr)
	require.NoError(t, err)

	pgd, err := tpm2.PolicyGetDigest{
		PolicySession: sess.Handle(),
	}.Execute(rwr)
	require.NoError(t, err)

	se, err := tinkcommon.NewPasswordSession(rwr, nil, nil, pgd.PolicyDigest.Buffer)
	require.NoError(t, err)

	aesKeyManager := NewTpmAesHmacAeadKeyManager(tpmDevice, se)
	err = registry.RegisterKeyManager(aesKeyManager)
	require.NoError(t, err)

	kh1, err := keyset.NewHandle(TpmAes128CtrHmacSha256Template())
	require.NoError(t, err)

	a, err := aead.New(kh1)
	require.NoError(t, err)

	e, err := a.Encrypt([]byte(plaintext), []byte("foo"))
	require.NoError(t, err)

	_, err = a.Decrypt(e, []byte("bar"))
	require.Error(t, err)
}

func TestAeadPassword(t *testing.T) {
	tpmDevice, err := simulator.Get()
	require.NoError(t, err)
	defer tpmDevice.Close()

	plaintext := "foo"

	rwr := transport.FromReadWriter(tpmDevice)

	sess, cleanup1, err := tpm2.PolicySession(rwr, tpm2.TPMAlgSHA256, 16, tpm2.Trial())
	require.NoError(t, err)
	defer cleanup1()

	pav := tpm2.PolicyAuthValue{
		PolicySession: sess.Handle(),
	}
	_, err = pav.Execute(rwr)
	require.NoError(t, err)

	pgd, err := tpm2.PolicyGetDigest{
		PolicySession: sess.Handle(),
	}.Execute(rwr)
	require.NoError(t, err)

	pswd := []byte("mypass")

	se, err := tinkcommon.NewPasswordSession(rwr, pswd, nil, pgd.PolicyDigest.Buffer)
	require.NoError(t, err)

	aesKeyManager := NewTpmAesHmacAeadKeyManager(tpmDevice, se)
	err = registry.RegisterKeyManager(aesKeyManager)
	require.NoError(t, err)

	kh1, err := keyset.NewHandle(TpmAes128CtrHmacSha256Template())
	require.NoError(t, err)

	a, err := aead.New(kh1)
	require.NoError(t, err)

	e, err := a.Encrypt([]byte(plaintext), nil)
	require.NoError(t, err)

	_, err = a.Decrypt(e, nil)
	require.NoError(t, err)
}

func TestAeadPasswordFail(t *testing.T) {
	tpmDevice, err := simulator.Get()
	require.NoError(t, err)
	defer tpmDevice.Close()

	plaintext := "foo"

	rwr := transport.FromReadWriter(tpmDevice)

	sess, cleanup1, err := tpm2.PolicySession(rwr, tpm2.TPMAlgSHA256, 16, tpm2.Trial())
	require.NoError(t, err)
	defer cleanup1()

	pav := tpm2.PolicyAuthValue{
		PolicySession: sess.Handle(),
	}
	_, err = pav.Execute(rwr)
	require.NoError(t, err)

	pgd, err := tpm2.PolicyGetDigest{
		PolicySession: sess.Handle(),
	}.Execute(rwr)
	require.NoError(t, err)

	pswd := []byte("mypass")

	se, err := tinkcommon.NewPasswordSession(rwr, pswd, nil, pgd.PolicyDigest.Buffer)
	require.NoError(t, err)

	aesKeyManager := NewTpmAesHmacAeadKeyManager(tpmDevice, se)
	err = registry.RegisterKeyManager(aesKeyManager)
	require.NoError(t, err)

	kh1, err := keyset.NewHandle(TpmAes128CtrHmacSha256Template())
	require.NoError(t, err)

	a, err := aead.New(kh1)
	require.NoError(t, err)

	e, err := a.Encrypt([]byte(plaintext), nil)
	require.NoError(t, err)

	_, err = a.Decrypt(e, nil)
	require.NoError(t, err)

	// simulate the wrong password

	// create an auth callback with the wrong password
	sess2, cleanup2, err := tpm2.PolicySession(rwr, tpm2.TPMAlgSHA256, 16, tpm2.Trial())
	require.NoError(t, err)
	defer cleanup2()

	pav2 := tpm2.PolicyAuthValue{
		PolicySession: sess2.Handle(),
	}
	_, err = pav2.Execute(rwr)
	require.NoError(t, err)

	pgd2, err := tpm2.PolicyGetDigest{
		PolicySession: sess2.Handle(),
	}.Execute(rwr)
	require.NoError(t, err)

	pswd2 := []byte("wrongpass")

	se2, err := tinkcommon.NewPasswordSession(rwr, pswd2, nil, pgd2.PolicyDigest.Buffer)
	require.NoError(t, err)

	// update the hmac key manager
	aesKeyManager.UpdateAuthCallback(se2)

	// try to encrypt
	a, err = aead.New(kh1)
	require.NoError(t, err)
	_, err = a.Encrypt([]byte(plaintext), nil)
	require.Error(t, err)
}

func TestAeadOwnerPassword(t *testing.T) {
	tpmDevice, err := simulator.Get()
	require.NoError(t, err)
	defer tpmDevice.Close()

	plaintext := "foo"

	rwr := transport.FromReadWriter(tpmDevice)

	ownerPwd := "bar"
	_, err = tpm2.HierarchyChangeAuth{
		AuthHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHOwner,
			Auth:   tpm2.PasswordAuth(nil),
		},
		NewAuth: tpm2.TPM2BAuth{
			Buffer: []byte(ownerPwd),
		},
	}.Execute(rwr)
	require.NoError(t, err)

	sess, cleanup1, err := tpm2.PolicySession(rwr, tpm2.TPMAlgSHA256, 16, tpm2.Trial())
	require.NoError(t, err)
	defer cleanup1()

	pav := tpm2.PolicyAuthValue{
		PolicySession: sess.Handle(),
	}
	_, err = pav.Execute(rwr)
	require.NoError(t, err)

	pgd, err := tpm2.PolicyGetDigest{
		PolicySession: sess.Handle(),
	}.Execute(rwr)
	require.NoError(t, err)

	pswd := []byte("mypass")

	se, err := tinkcommon.NewPasswordSession(rwr, pswd, []byte(ownerPwd), pgd.PolicyDigest.Buffer)
	require.NoError(t, err)

	aesKeyManager := NewTpmAesHmacAeadKeyManager(tpmDevice, se)
	err = registry.RegisterKeyManager(aesKeyManager)
	require.NoError(t, err)

	kh1, err := keyset.NewHandle(TpmAes128CtrHmacSha256Template())
	require.NoError(t, err)

	a, err := aead.New(kh1)
	require.NoError(t, err)

	e, err := a.Encrypt([]byte(plaintext), nil)
	require.NoError(t, err)

	_, err = a.Decrypt(e, nil)
	require.NoError(t, err)
}

func TestAeadOwnerPasswordFail(t *testing.T) {
	tpmDevice, err := simulator.Get()
	require.NoError(t, err)
	defer tpmDevice.Close()

	rwr := transport.FromReadWriter(tpmDevice)

	ownerPwd := "bar"
	badownerPwd := "barbar"
	_, err = tpm2.HierarchyChangeAuth{
		AuthHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHOwner,
			Auth:   tpm2.PasswordAuth(nil),
		},
		NewAuth: tpm2.TPM2BAuth{
			Buffer: []byte(ownerPwd),
		},
	}.Execute(rwr)
	require.NoError(t, err)

	sess, cleanup1, err := tpm2.PolicySession(rwr, tpm2.TPMAlgSHA256, 16, tpm2.Trial())
	require.NoError(t, err)
	defer cleanup1()

	pav := tpm2.PolicyAuthValue{
		PolicySession: sess.Handle(),
	}
	_, err = pav.Execute(rwr)
	require.NoError(t, err)

	pgd, err := tpm2.PolicyGetDigest{
		PolicySession: sess.Handle(),
	}.Execute(rwr)
	require.NoError(t, err)

	pswd := []byte("mypass")

	se, err := tinkcommon.NewPasswordSession(rwr, pswd, []byte(badownerPwd), pgd.PolicyDigest.Buffer)
	require.NoError(t, err)

	aesKeyManager := NewTpmAesHmacAeadKeyManager(tpmDevice, se)
	err = registry.RegisterKeyManager(aesKeyManager)
	require.NoError(t, err)

	_, err = keyset.NewHandle(TpmAes128CtrHmacSha256Template())
	require.Error(t, err)
}

func TestAeadPCR(t *testing.T) {
	tpmDevice, err := simulator.Get()
	require.NoError(t, err)
	defer tpmDevice.Close()

	pcrs := []uint{23}
	plaintext := "foo"

	rwr := transport.FromReadWriter(tpmDevice)

	sel := tpm2.TPMLPCRSelection{
		PCRSelections: []tpm2.TPMSPCRSelection{
			{
				Hash:      tpm2.TPMAlgSHA256,
				PCRSelect: tpm2.PCClientCompatible.PCRs(pcrs...),
			},
		},
	}

	sess, cleanup1, err := tpm2.PolicySession(rwr, tpm2.TPMAlgSHA256, 16, tpm2.Trial())
	require.NoError(t, err)
	defer cleanup1()

	pav := tpm2.PolicyPCR{
		PolicySession: sess.Handle(),
		Pcrs:          sel,
	}
	_, err = pav.Execute(rwr)
	require.NoError(t, err)

	pgd, err := tpm2.PolicyGetDigest{
		PolicySession: sess.Handle(),
	}.Execute(rwr)
	require.NoError(t, err)

	se, err := tinkcommon.NewPCRSession(rwr, nil, nil, pgd.PolicyDigest.Buffer, sel.PCRSelections, nil)
	require.NoError(t, err)
	require.NoError(t, err)

	hmacKeyManager := NewTpmAesHmacAeadKeyManager(tpmDevice, se)
	err = registry.RegisterKeyManager(hmacKeyManager)
	require.NoError(t, err)

	kh1, err := keyset.NewHandle(TpmAes128CtrHmacSha256Template())
	require.NoError(t, err)

	a, err := aead.New(kh1)
	require.NoError(t, err)

	e, err := a.Encrypt([]byte(plaintext), nil)
	require.NoError(t, err)

	d, err := a.Decrypt(e, nil)
	require.NoError(t, err)

	require.Equal(t, d, []byte(plaintext))
}

func TestAeadPCRFail(t *testing.T) {
	tpmDevice, err := simulator.Get()
	require.NoError(t, err)
	defer tpmDevice.Close()

	pcrs := []uint{23}
	plaintext := "foo"

	rwr := transport.FromReadWriter(tpmDevice)

	sel := tpm2.TPMLPCRSelection{
		PCRSelections: []tpm2.TPMSPCRSelection{
			{
				Hash:      tpm2.TPMAlgSHA256,
				PCRSelect: tpm2.PCClientCompatible.PCRs(pcrs...),
			},
		},
	}

	sess, cleanup1, err := tpm2.PolicySession(rwr, tpm2.TPMAlgSHA256, 16, tpm2.Trial())
	require.NoError(t, err)
	defer cleanup1()

	pav := tpm2.PolicyPCR{
		PolicySession: sess.Handle(),
		Pcrs:          sel,
	}
	_, err = pav.Execute(rwr)
	require.NoError(t, err)

	pgd, err := tpm2.PolicyGetDigest{
		PolicySession: sess.Handle(),
	}.Execute(rwr)
	require.NoError(t, err)

	se, err := tinkcommon.NewPCRSession(rwr, nil, nil, pgd.PolicyDigest.Buffer, sel.PCRSelections, nil)
	require.NoError(t, err)
	require.NoError(t, err)

	hmacKeyManager := NewTpmAesHmacAeadKeyManager(tpmDevice, se)
	err = registry.RegisterKeyManager(hmacKeyManager)
	require.NoError(t, err)

	kh1, err := keyset.NewHandle(TpmAes128CtrHmacSha256Template())
	require.NoError(t, err)

	a, err := aead.New(kh1)
	require.NoError(t, err)

	e, err := a.Encrypt([]byte(plaintext), nil)
	require.NoError(t, err)

	d, err := a.Decrypt(e, nil)
	require.NoError(t, err)

	require.Equal(t, d, []byte(plaintext))

	// now extend the pcr

	pcrReadRsp, err := tpm2.PCRRead{
		PCRSelectionIn: tpm2.TPMLPCRSelection{
			PCRSelections: []tpm2.TPMSPCRSelection{
				{
					Hash:      tpm2.TPMAlgSHA256,
					PCRSelect: tpm2.PCClientCompatible.PCRs(pcrs...),
				},
			},
		},
	}.Execute(rwr)
	require.NoError(t, err)

	_, err = tpm2.PCRExtend{
		PCRHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMHandle(uint32(pcrs[0])),
			Auth:   tpm2.PasswordAuth(nil),
		},
		Digests: tpm2.TPMLDigestValues{
			Digests: []tpm2.TPMTHA{
				{
					HashAlg: tpm2.TPMAlgSHA256,
					Digest:  pcrReadRsp.PCRValues.Digests[0].Buffer,
				},
			},
		},
	}.Execute(rwr)
	require.NoError(t, err)

	_, err = a.Decrypt(e, nil)
	require.Error(t, err)
}
