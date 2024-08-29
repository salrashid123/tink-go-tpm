package signature

import (
	"fmt"

	"google.golang.org/protobuf/proto"

	tinktpmprotopb "github.com/salrashid123/tink-go-tpm/v2/proto"

	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
)

func create_RSA_SSA_PKCS1_Template(prefixType tinkpb.OutputPrefixType, hashType tinktpmprotopb.HashType, modulusSizeInBits uint32) *tinkpb.KeyTemplate {
	keyFormat := &tinktpmprotopb.RsaSsaPkcs1KeyTpmFormat{
		Params: &tinktpmprotopb.RsaSsaPkcs1Params{
			HashType: hashType,
		},
		ModulusSizeInBits: modulusSizeInBits,
		PublicExponent:    []byte{0x01, 0x00, 0x01}, // 65537 aka F4
	}
	serializedFormat, err := proto.Marshal(keyFormat)
	if err != nil {
		fmt.Errorf("failed to marshal key format: %s", err)
		// exit or
		return &tinkpb.KeyTemplate{}
	}
	return &tinkpb.KeyTemplate{
		TypeUrl:          rsaSSAPKCS1SignerTypeURL,
		OutputPrefixType: prefixType,
		Value:            serializedFormat,
	}
}

// RSA_SSA_PKCS1_3072_SHA256_F4_Key_Template is a KeyTemplate that generates a new RSA SSA PKCS1 private key with the following
// parameters:
//   - Modulus size in bits: 3072.
//   - Hash function: SHA256.
//   - Public Exponent: 65537 (aka F4).
//   - OutputPrefixType: TINK
func RSA_SSA_PKCS1_3072_SHA256_F4_Key_Template() *tinkpb.KeyTemplate {
	return create_RSA_SSA_PKCS1_Template(tinkpb.OutputPrefixType_TINK, tinktpmprotopb.HashType_SHA256, 3072)
}

// RSA_SSA_PKCS1_2048_SHA256_F4_Key_Template is a KeyTemplate that generates a new RSA SSA PKCS1 private key with the following
// parameters:
//   - Modulus size in bits: 3072.
//   - Hash function: SHA256.
//   - Public Exponent: 65537 (aka F4).
//   - OutputPrefixType: TINK
func RSA_SSA_PKCS1_2048_SHA256_F4_Key_Template() *tinkpb.KeyTemplate {
	return create_RSA_SSA_PKCS1_Template(tinkpb.OutputPrefixType_TINK, tinktpmprotopb.HashType_SHA256, 2048)
}

// RSA_SSA_PKCS1_3072_SHA256_F4_RAW_Key_Template is a KeyTemplate that generates a new RSA SSA PKCS1 private key with the following
// parameters:
//   - Modulus size in bits: 3072.
//   - Hash function: SHA256.
//   - Public Exponent: 65537 (aka F4).
//   - OutputPrefixType: RAW
func RSA_SSA_PKCS1_3072_SHA256_F4_RAW_Key_Template() *tinkpb.KeyTemplate {
	return create_RSA_SSA_PKCS1_Template(tinkpb.OutputPrefixType_RAW, tinktpmprotopb.HashType_SHA256, 3072)
}

// RSA_SSA_PKCS1_4096_SHA512_F4_Key_Template is a KeyTemplate that generates a new RSA SSA PKCS1 private key with the following
// parameters:
//   - Modulus size in bits: 4096.
//   - Hash function: SHA512.
//   - Public Exponent: 65537 (aka F4).
//   - OutputPrefixType: TINK
func RSA_SSA_PKCS1_4096_SHA512_F4_Key_Template() *tinkpb.KeyTemplate {
	return create_RSA_SSA_PKCS1_Template(tinkpb.OutputPrefixType_TINK, tinktpmprotopb.HashType_SHA512, 4096)
}

// RSA_SSA_PKCS1_4096_SHA512_F4_RAW_Key_Template is a KeyTemplate that generates a new RSA SSA PKCS1 private key with the following
// parameters:
//   - Modulus size in bits: 4096.
//   - Hash function: SHA512.
//   - Public Exponent: 65537 (aka F4).
//   - OutputPrefixType: RAW
func RSA_SSA_PKCS1_4096_SHA512_F4_RAW_Key_Template() *tinkpb.KeyTemplate {
	return create_RSA_SSA_PKCS1_Template(tinkpb.OutputPrefixType_RAW, tinktpmprotopb.HashType_SHA512, 4096)
}
