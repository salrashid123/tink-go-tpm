package signature

import (
	"testing"

	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/stretchr/testify/require"

	tinkcommon "github.com/salrashid123/tink-go-tpm/v2/common"
	"github.com/tink-crypto/tink-go/v2/core/registry"
	"github.com/tink-crypto/tink-go/v2/keyset"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
)

func TestSign(t *testing.T) {
	//tpmDevice, err := tinkcommon.OpenTPM("127.0.0.1:2321")  // rsa keys larger than 2048 work with this
	//   but not the go-tpm-tools simulator below... i have to figure this out later
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

	rsaKeyManager := NewRSASSAPKCS1SignerTpmKeyManager(tpmDevice, se)
	err = registry.RegisterKeyManager(rsaKeyManager)
	require.NoError(t, err)

	tests := []struct {
		name     string
		template *tinkpb.KeyTemplate
	}{
		{"RSA_SSA_PKCS1_2048_SHA256_F4_Key_Template", RSA_SSA_PKCS1_2048_SHA256_F4_Key_Template()},

		// {"RSA_SSA_PKCS1_3072_SHA256_F4_Key_Template", RSA_SSA_PKCS1_3072_SHA256_F4_Key_Template()},
		// {"RSA_SSA_PKCS1_3072_SHA256_F4_RAW_Key_Template", RSA_SSA_PKCS1_3072_SHA256_F4_RAW_Key_Template()},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {

			kh1, err := keyset.NewHandle(tc.template)
			require.NoError(t, err)

			s, err := NewSigner(kh1)
			require.NoError(t, err)

			msg := []byte([]byte(plaintext))
			_, err = s.Sign(msg)
			require.NoError(t, err)
		})
	}
}

func TestSignFail(t *testing.T) {
	//tpmDevice, err := tinkcommon.OpenTPM("127.0.0.1:2321")
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

	rsaKeyManager := NewRSASSAPKCS1SignerTpmKeyManager(tpmDevice, se)
	err = registry.RegisterKeyManager(rsaKeyManager)
	require.NoError(t, err)

	tests := []struct {
		name     string
		template *tinkpb.KeyTemplate
	}{
		{"RSA_SSA_PKCS1_2048_SHA256_F4_Key_Template", RSA_SSA_PKCS1_2048_SHA256_F4_Key_Template()},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {

			kh1, err := keyset.NewHandle(tc.template)
			require.NoError(t, err)

			s, err := NewSigner(kh1)
			require.NoError(t, err)

			// abruptly change the owner auth
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

			msg := []byte([]byte(plaintext))
			_, err = s.Sign(msg)
			require.Error(t, err)
		})
	}
}
