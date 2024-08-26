package mac

import (
	"testing"

	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/stretchr/testify/require"

	tinkcommon "github.com/salrashid123/tink-go-tpm/v2/common"
	"github.com/tink-crypto/tink-go/v2/core/registry"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/mac"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
)

func TestMac(t *testing.T) {
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

	hmacKeyManager := NewTPMHMACKeyManager(tpmDevice, se)
	err = registry.RegisterKeyManager(hmacKeyManager)
	require.NoError(t, err)

	tests := []struct {
		name     string
		template *tinkpb.KeyTemplate
	}{
		{"HMACSHA256Tag256KeyTPMTemplate", HMACSHA256Tag256KeyTPMTemplate()},
		{"HMACSHA512Tag256KeyTPMNoPrefixTemplate", HMACSHA512Tag256KeyTPMNoPrefixTemplate()},
		{"HMACSHA512Tag256KeyTPMTemplate", HMACSHA512Tag256KeyTPMTemplate()},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {

			kh1, err := keyset.NewHandle(tc.template)
			require.NoError(t, err)

			a, err := mac.New(kh1)
			require.NoError(t, err)

			mf, err := a.ComputeMAC([]byte(plaintext))
			require.NoError(t, err)

			err = a.VerifyMAC(mf, []byte(plaintext))
			require.NoError(t, err)
		})
	}

}

func TestMacFail(t *testing.T) {
	tpmDevice, err := simulator.Get()
	require.NoError(t, err)
	defer tpmDevice.Close()

	plaintext := "foo"
	otherplaintext := "bar"

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

	hmacKeyManager := NewTPMHMACKeyManager(tpmDevice, se)
	err = registry.RegisterKeyManager(hmacKeyManager)
	require.NoError(t, err)

	kh1, err := keyset.NewHandle(HMACSHA256Tag256KeyTPMTemplate())
	require.NoError(t, err)

	a, err := mac.New(kh1)
	require.NoError(t, err)

	mf, err := a.ComputeMAC([]byte(plaintext))
	require.NoError(t, err)

	err = a.VerifyMAC(mf, []byte(otherplaintext))
	require.Error(t, err)
}

func TestMacPassword(t *testing.T) {
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

	hmacKeyManager := NewTPMHMACKeyManager(tpmDevice, se)
	err = registry.RegisterKeyManager(hmacKeyManager)
	require.NoError(t, err)

	kh1, err := keyset.NewHandle(HMACSHA256Tag256KeyTPMTemplate())
	require.NoError(t, err)

	a, err := mac.New(kh1)
	require.NoError(t, err)

	mf, err := a.ComputeMAC([]byte(plaintext))
	require.NoError(t, err)

	err = a.VerifyMAC(mf, []byte(plaintext))
	require.NoError(t, err)
}

func TestMacOwnerPassword(t *testing.T) {
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

	se, err := tinkcommon.NewPasswordSession(rwr, nil, []byte(ownerPwd), pgd.PolicyDigest.Buffer)
	require.NoError(t, err)

	hmacKeyManager := NewTPMHMACKeyManager(tpmDevice, se)
	err = registry.RegisterKeyManager(hmacKeyManager)
	require.NoError(t, err)

	kh1, err := keyset.NewHandle(HMACSHA256Tag256KeyTPMTemplate())
	require.NoError(t, err)

	a, err := mac.New(kh1)
	require.NoError(t, err)

	mf, err := a.ComputeMAC([]byte(plaintext))
	require.NoError(t, err)

	err = a.VerifyMAC(mf, []byte(plaintext))
	require.NoError(t, err)
}

func TestMacOwnerPasswordFail(t *testing.T) {
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

	se, err := tinkcommon.NewPasswordSession(rwr, nil, []byte(badownerPwd), pgd.PolicyDigest.Buffer)
	require.NoError(t, err)

	hmacKeyManager := NewTPMHMACKeyManager(tpmDevice, se)
	err = registry.RegisterKeyManager(hmacKeyManager)
	require.NoError(t, err)

	_, err = keyset.NewHandle(HMACSHA256Tag256KeyTPMTemplate())
	require.Error(t, err)
}

func TestMacPasswordFail(t *testing.T) {
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

	hmacKeyManager := NewTPMHMACKeyManager(tpmDevice, se)
	err = registry.RegisterKeyManager(hmacKeyManager)
	require.NoError(t, err)

	kh1, err := keyset.NewHandle(HMACSHA256Tag256KeyTPMTemplate())
	require.NoError(t, err)

	a, err := mac.New(kh1)
	require.NoError(t, err)

	mf, err := a.ComputeMAC([]byte(plaintext))
	require.NoError(t, err)

	err = a.VerifyMAC(mf, []byte(plaintext))
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
	hmacKeyManager.UpdateAuthCallback(se2)

	// try to create a mac
	a, err = mac.New(kh1)
	require.NoError(t, err)

	_, err = a.ComputeMAC([]byte(plaintext))
	require.Error(t, err)
}

func TestMacPCR(t *testing.T) {
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

	hmacKeyManager := NewTPMHMACKeyManager(tpmDevice, se)
	err = registry.RegisterKeyManager(hmacKeyManager)
	require.NoError(t, err)

	kh1, err := keyset.NewHandle(HMACSHA256Tag256KeyTPMTemplate())
	require.NoError(t, err)

	a, err := mac.New(kh1)
	require.NoError(t, err)

	mf, err := a.ComputeMAC([]byte(plaintext))
	require.NoError(t, err)

	err = a.VerifyMAC(mf, []byte(plaintext))
	require.NoError(t, err)
}

func TestMacPCRFail(t *testing.T) {
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

	hmacKeyManager := NewTPMHMACKeyManager(tpmDevice, se)
	err = registry.RegisterKeyManager(hmacKeyManager)
	require.NoError(t, err)

	kh1, err := keyset.NewHandle(HMACSHA256Tag256KeyTPMTemplate())
	require.NoError(t, err)

	a, err := mac.New(kh1)
	require.NoError(t, err)

	mf, err := a.ComputeMAC([]byte(plaintext))
	require.NoError(t, err)

	err = a.VerifyMAC(mf, []byte(plaintext))
	require.NoError(t, err)

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

	mf, err = a.ComputeMAC([]byte(plaintext))
	require.Error(t, err)
}
