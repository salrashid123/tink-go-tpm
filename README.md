# TINK Go TPM extension 


An encryption library for [Google Tink](https://github.com/google/tink) which uses `Trusted Platform Modules (TPM)` based keys to perform operations.

Currently, while TINK itself supports a variety of [key types](https://developers.google.com/tink/supported-key-types), only the following are supported in this library

* **AEAD**: `AES-CTR-HMAC`
* **MAC**: `HMAC-SHA2256`
* **Signature**: `RSA-SSA-PKCS1`

>> NOTE: this repo is NOT supported by google

see FR: [issue #389](https://github.com/google/tink/issues/389)

### AEAD: AES-CTR-HMAC 

Internally, this mode generates two tpm-bound keys:  `AES-CTR` and an `HMAC` key.  These are used to generate the AEAD composite primitive.  TPM2 [does not support AES-GCM](https://github.com/tpm2-software/tpm2-tools/blob/master/man/common/alg.md#modes) so we have to use generate the AEAD using these two keys.

```golang
import (
	"github.com/google/go-tpm/tpm2"
	tpmaead "github.com/salrashid123/tink-go-tpm/v2/aead"
	tinkcommon "github.com/salrashid123/tink-go-tpm/v2/common"
	"github.com/tink-crypto/tink-go/v2/core/registry"
	"github.com/tink-crypto/tink-go/v2/mac"

	"github.com/tink-crypto/tink-go/v2/keyset"
)

// create a policy session to define any constraints (eg, password or pcr policy), the folloing example doesn't use any
	sess, cleanup1, err := tpm2.PolicySession(rwr, tpm2.TPMAlgSHA256, 16, tpm2.Trial())
	defer cleanup1()

	pav := tpm2.PolicyAuthValue{
		PolicySession: sess.Handle(),
	}
	_, err = pav.Execute(rwr)

// calculate the digest for this policy
	pgd, err := tpm2.PolicyGetDigest{
		PolicySession: sess.Handle(),
	}.Execute(rwr)

// configure the session, in this case its a policysession is password with nil value as the password (i.,e no password):
	se, err := tinkcommon.NewPasswordSession(rwr, nil, pgd.PolicyDigest.Buffer)

// bind the session to the keymanager (yeah, this isn't great but i coudn't figure out how to do this otherwise; see section at the end of the repo)
	aesKeyManager := tpmaead.NewTpmAesHmacAeadKeyManager(rwc, se)
	err = registry.RegisterKeyManager(aesKeyManager)

// now just use as normal aead
	kh1, err := keyset.NewHandle(tpmaead.TpmAes128CtrHmacSha256Template())
	//kh1, err := keyset.NewHandle(tpmaead.TpmAes256CtrHmacSha256Template())
	//kh1, err := keyset.NewHandle(tpmaead.TpmAes128CtrHmacSha256NoTemplate())   
	a, err := aead.New(kh1)

	e, err := a.Encrypt([]byte(plaintext), nil)

	log.Printf("Encrypted %s\n", base64.StdEncoding.EncodeToString(e))

	d, err := av.Decrypt(e, nil)

	log.Printf("Decrypted %s\n", string(d))
```

See the `example/` folder.  If you would rather just test with a software TPM, see the section below.

```bash
### encrypt
$ go run aes/nopassword/encrypt/main.go \
   --encryptedFile=/tmp/encrypted.dat \
   --keySet=/tmp/keyset.json \
   --tpm-path="127.0.0.1:2321"

   2024/08/24 15:40:05     Encrypted AdDGpzzPIFkxupNOz67XIIeVBbp7KaLl90CW1pxAjXU5zHU/fFc3QgvqgyLXwNw+7CuUIlpXEUg=

### decrypt
$ go run aes/nopassword/decrypt/main.go --encryptedFile=/tmp/encrypted.dat \
   --keySet=/tmp/keyset.json \
   --tpm-path="127.0.0.1:2321"

   2024/08/24 15:40:35 decrypted foo
```

### MAC: HMAC-SHA2

Internally, this generates an hmac inside the tpm and uses the tpm itself to create the mac calculations.

```golang
import (
	"github.com/google/go-tpm/tpm2"
	tpmmac "github.com/salrashid123/tink-go-tpm/v2/mac"
	tinkcommon "github.com/salrashid123/tink-go-tpm/v2/common"
	"github.com/tink-crypto/tink-go/v2/core/registry"
	"github.com/tink-crypto/tink-go/v2/mac"

	"github.com/tink-crypto/tink-go/v2/keyset"
)

// create a policy session to define any constraints (eg, password or pcr policy), the folloing example doesn't use any
	sess, cleanup1, err := tpm2.PolicySession(rwr, tpm2.TPMAlgSHA256, 16, tpm2.Trial())
	defer cleanup1()

	pav := tpm2.PolicyAuthValue{
		PolicySession: sess.Handle(),
	}
	_, err = pav.Execute(rwr)

// calculate the digest for this policy
	pgd, err := tpm2.PolicyGetDigest{
		PolicySession: sess.Handle(),
	}.Execute(rwr)

// configure the session, in this case its a policysession is password with nil value as the password (i.,e no password):
	se, err := tinkcommon.NewPasswordSession(rwr, nil, pgd.PolicyDigest.Buffer)

// bind the session to the keymanager (yeah, this isn't great but i coudn't figure out how to do this otherwise; see section at the end of the repo)
	hmacKeyManager := tpmmac.NewTPMHMACKeyManager(rwc, se)
	err = registry.RegisterKeyManager(hmacKeyManager)

// get a new  hmac key of any template type, hmac-sha256 or hmac-sha512
	kh1, err := keyset.NewHandle(tpmmac.HMACSHA256Tag256KeyTPMTemplate())
	//kh1, err := keyset.NewHandle(tpmmac.HMACSHA256Tag256KeyTPMNoPrefixTemplate())
	//kh1, err := keyset.NewHandle(tpmmac.HMACSHA512Tag256KeyTPMTemplate())

// use the new key to compute a mac
	a, err := mac.New(kh1)
	tag, err := a.ComputeMAC([]byte("foo"))
	fmt.Printf("    MAC %s\n", base64.RawStdEncoding.EncodeToString(tag))
```

See the `example/` folder.  If you would rather just test with a software TPM, see the section below.


```bash
# create
$ go run hmac/nopassword/create/main.go \
   --tpm-path="127.0.0.1:2321" --macFile=mac.dat \
   --plaintext=foo --keySet=keyset.json

2024/06/21 09:59:33     MAC Adon8pom2yPtM8V8yMZM+BOR/uq1quG4qwGq4l9YzZ6Qspkqpw

# verify
$ go run hmac/nopassword/verify/main.go \
   --tpm-path="127.0.0.1:2321" --macFile=mac.dat \
   --plaintext=foo --keySet=keyset.json

2024/06/21 10:01:05 Verified
```  

---


### Signature: RSA-SSA-PKCS1

Internally, this generates an RSA inside the tpm and uses the tpm itself to create the signature.

The public key is also written to a tink keyset and it can be used without a TPM to verify

```golang
import (
	"github.com/google/go-tpm/tpm2"
	tpmsign "github.com/salrashid123/tink-go-tpm/v2/signature"
	tinkcommon "github.com/salrashid123/tink-go-tpm/v2/common"
	"github.com/tink-crypto/tink-go/v2/core/registry"

	"github.com/tink-crypto/tink-go/v2/keyset"
)

// create a policy session to define any constraints (eg, password or pcr policy), the folloing example doesn't use any
	sess, cleanup1, err := tpm2.PolicySession(rwr, tpm2.TPMAlgSHA256, 16, tpm2.Trial())
	defer cleanup1()

	pav := tpm2.PolicyAuthValue{
		PolicySession: sess.Handle(),
	}
	_, err = pav.Execute(rwr)

// calculate the digest for this policy
	pgd, err := tpm2.PolicyGetDigest{
		PolicySession: sess.Handle(),
	}.Execute(rwr)

// configure the session, in this case its a policysession is password with nil value as the password (i.,e no password):
	se, err := tinkcommon.NewPasswordSession(rwr, nil, pgd.PolicyDigest.Buffer)

// bind the session to the keymanager
	rsaKeyManager := tpmsign.NewRSASSAPKCS1SignerTpmKeyManager(rwc, se)
	err = registry.RegisterKeyManager(rsaKeyManager)

// create a keyset from template
	kh, err := keyset.NewHandle(tpmsign.RSA_SSA_PKCS1_2048_SHA256_F4_Key_Template()) // Other key templates can also be used.

// get a signer
	s, err := tpmsign.NewSigner(kh)

// sign
	sig, err := s.Sign(msg)

	fmt.Printf("Signature: %s\n", base64.StdEncoding.EncodeToString(sig))


// to verify, get the public key (you can write this safely to anywhere and you dont' need a tpm to verify)
	pubkh, err := kh.Public()

// acquire the verifier key manger
	rsaVerifierKeyManager := tpmsign.NewRSASSAPKCS1VerifierTpmKeyManager(nil, nil)
	err = registry.RegisterKeyManager(rsaVerifierKeyManager)

// verify
	v, err := tpmsign.NewVerifier(pubkh)
	if err := v.Verify(sig, msg); err != nil {
		log.Fatal(err)
	}
	fmt.Println("Verified")
```

See the `example/` folder.  If you would rather just test with a software TPM, see the section below.


```bash
# sign
$ go run sign/rsa/nopassword/sign/main.go \
   --tpm-path="127.0.0.1:2321" --publicKeySet=/tmp/public.json --privateKeySet=/tmp/private.json \
   --plaintext=foo  --signatureFile=/tmp/signature.dat --dataFile=/tmp/data.txt

# verify
$ go run sign/rsa/nopassword/verify/main.go \
    --publicKeySet=/tmp/public.json \
    --signatureFile=/tmp/signature.dat --dataFile=/tmp/data.txt
```  

### With Policy

You can bind the key to certain TPM policies such as requiring a passphrase or specific TPM PCR values to be present to do any operations.  Basically any TPM policy you define as a callback

#### Policy AuthValue (password)
 
To use a password policy

- `AES-CTR-HMAC`

```bash
$ go run aes/password_policy/encrypt/main.go \
   --encryptedFile=/tmp/encrypted.dat \
   --keySet=/tmp/keyset.json \
   --password=testpswd 

$ go run aes/password_policy/decrypt/main.go  \
   --encryptedFile=/tmp/encrypted.dat \
   --keySet=/tmp/keyset.json \
   --password=testpswd  
```

- `HMAC`

```bash
# create
$ go run hmac/password_policy/create/main.go \
   --tpm-path="127.0.0.1:2321" --password=testpswd --macFile=mac.dat \
   --plaintext=foo --keySet=keyset.json

# verify
$ go run hmac/password_policy/verify/main.go \
   --tpm-path="127.0.0.1:2321" --password=testpswd --macFile=mac.dat \
   --plaintext=foo --keySet=keyset.json
```

#### Policy PCR 

If you want to bind the encryption or hmac to a specific PCR value (eg pcr=23), and if your pcr's are currently:

```bash
 tpm2_pcrread sha256:23
  sha256:
    23: 0xF5A5FD42D16A20302798EF6ED309979B43003D2320D9F0E8EA9831A92759FB4B
```

Then see the examples below for the binding commands

- `AES-CTR-HMAC`

```bash
$ go run aes/pcr_policy/encrypt/main.go \
   --encryptedFile=/tmp/encrypted.dat \
   --keySet=/tmp/keyset.json \
   --pcrList=0,23 


$ go run aes/pcr_policy/decrypt/main.go  \
   --encryptedFile=/tmp/encrypted.dat \
   --keySet=/tmp/keyset.json   --pcrList=0,23 
```

- `HMAC`

To test with a PCR binding to pcr-23

```bash
# create
$ go run hmac/pcr_policy/create/main.go \
   --tpm-path="127.0.0.1:2321" --pcrList=0,23  --macFile=mac.dat \
   --plaintext=foo --keySet=keyset.json

# verify
$ go run hmac/pcr_policy/verify/main.go \
   --tpm-path="127.0.0.1:2321" --pcrList=0,23  --macFile=mac.dat \
   --plaintext=foo --keySet=keyset.json
```

now test with an invalid pcr binding.  The error below indicates that the policy digest the key was initially created with (as encoded into the key (see `tinktpm.proto`)) does not match what was calculated in the session callback.  Even if this check was bypassed, the hmac would fail since the key itself on the TPM requires a specific PCR value

```bash
# if using software TPM:
# export TPM2TOOLS_TCTI="swtpm:port=2321"
$ tpm2_pcrread sha256:23
  sha256:
    23: F5A5FD42D16A20302798EF6ED309979B43003D2320D9F0E8EA9831A92759FB4B

## to mutate the pcr value
$ tpm2_pcrextend 23:sha256=0xF5A5FD42D16A20302798EF6ED309979B43003D2320D9F0E8EA9831A92759FB4B

$ tpm2_pcrread sha256:23
  sha256:
    23: 0xDB56114E00FDD4C1F85C892BF35AC9A89289AAECB1EBD0A96CDE606A748B5D71

$ go run hmac/pcr_policy/verify/main.go \
   --tpm-path="127.0.0.1:2321" --pcr=23 --macFile=mac.dat \
   --plaintext=foo --keySet=keyset.json
```


The following error compares the policy that was encoded in the TinkKeyset vs what the live calculated runtime policy is.  A possible reason for this error is that the PCR values the key was bound to does not match what the current pcrs are

```bash
aead_factory: cannot obtain primitive set: registry.PrimitivesWithKeyManager: cannot get primitive from key: error creating key: policy digest mismatch in key 12345, in session: 6789
exit status 1
```

This error usually indicates you are trying to bind to a specific pcr value that is not currently present on the TPM

```bash
Error computing mac: TPM_RC_VALUE (parameter 1): value is out of range or is not correct for the context
aead_factory: decryption failed
```

#### KeyManager Policy Callback

One notable limitation of this implementation is that the KeyManager itself holds the session callback references.  This was done because there is no way to serialize a session and it should not get encoded into the Key that deserialized inside the subtle

So for now, when you register the key manager, you have to specify singleton password and callback:

```golang
	pav := tpm2.PolicyAuthValue{
		PolicySession: sess.Handle(),
	}
	_, err = pav.Execute(rwr)

	pgd, err := tpm2.PolicyGetDigest{
		PolicySession: sess.Handle(),
	}.Execute(rwr)

	se, err := tinkcommon.NewPasswordSession(rwr, nil, pgd.PolicyDigest.Buffer, []byte(*sensitive))

	hmacKeyManager := tinktpm.NewTPMHMACKeyManager(rwc, se)   // the callback is specified at the keymanager level
	err = registry.RegisterKeyManager(hmacKeyManager)   // this is a singleton (you can't register twice...)

	kh1, err := keyset.NewHandle(tinktpm.HMACSHA256Tag256KeyTPMNoPrefixTemplate())
```

this limitation maynot be a big deal but it does cause issues if you attempt to create and use multiple keys with different policies.

A workaround for this is to update the singleton KeyManager with a new AuthCallback using the `UpdateAuthCallback(ac tinkcommon.AuthCallback)`.  You can find an example of this approach in the unit-tests.  Note that its still one keymanager with one policy in effect at anytime anyway.




### Setup with software TPM

If you want to use a software TPM to test with instead of a real one:

```bash
rm -rf /tmp/myvtpm && mkdir /tmp/myvtpm
sudo swtpm_setup --tpmstate /tmp/myvtpm --tpm2 --create-ek-cert 
sudo swtpm socket --tpmstate dir=/tmp/myvtpm --tpm2 --server type=tcp,port=2321 --ctrl type=tcp,port=2322 --flags not-need-init,startup-clear  --log level=5

# export TPM2TOOLS_TCTI="swtpm:port=2321"
## then set the TPM flag in the examples to --tpm-path="127.0.0.1:2321"
```

### Key Types

While the key type used here is custom: 

* `"type.googleapis.com/github.salrashid123.tink-go-tpm.HmacTpmKey"`
* `"type.googleapis.com/github.salrashid123.tink-go-tpm.AesCtrHmacAeadTpmKey"`
* `"type.googleapis.com/github.salrashid123.tink-go-tpm.RsaSsaPkcs1PublicTpmKey"`
* `"type.googleapis.com/github.salrashid123.tink-go-tpm.RsaSsaPkcs1PrivateTpmKey"`

you can still  use `tinkkey` for listing specifications (you can't use it to generate a new key since tinkey doens't know about this type...)

```bash

# hmac
$ tinkey list-keyset --in keyset.json 
primary_key_id: 3163174926
key_info {
  type_url: "type.googleapis.com/github.salrashid123.tink-go-tpm.HmacTpmKey"
  status: ENABLED
  key_id: 3163174926
  output_prefix_type: TINK
}

## ead
$ tinkey list-keyset --in keyset.json 
primary_key_id: 1643958734
key_info {
  type_url: "type.googleapis.com/github.salrashid123.tink-go-tpm.AesCtrHmacAeadTpmKey"
  status: ENABLED
  key_id: 1643958734
  output_prefix_type: TINK
}


### rsa
$ tinkey list-keyset --in /tmp/private.json 
primary_key_id: 623370012
key_info {
  type_url: "type.googleapis.com/github.salrashid123.tink-go-tpm.RsaSsaPkcs1PrivateTpmKey"
  status: ENABLED
  key_id: 623370012
  output_prefix_type: TINK
}

$ tinkey list-keyset --in /tmp/public.json 
primary_key_id: 623370012
key_info {
  type_url: "type.googleapis.com/github.salrashid123.tink-go-tpm.RsaSsaPkcs1PublicTpmKey"
  status: ENABLED
  key_id: 623370012
  output_prefix_type: TINK
}

```

as JSON, they are:

```json
{
	"primaryKeyId": 3163174926,
	"key": [
		{
			"keyData": {
				"typeUrl": "type.googleapis.com/github.salrashid123.tink-go-tpm.HmacTpmKey",
				"value": "EAEa3QMa...",
				"keyMaterialType": "SYMMETRIC"
			},
			"status": "ENABLED",
			"keyId": 3163174926,
			"outputPrefixType": "TINK"
		}
	]
}
```

AEAD:

```json
{
	"primaryKeyId": 1643958734,
	"key": [
		{
			"keyData": {
				"typeUrl": "type.googleapis.com/github.salrashid123.tink-go-tpm.AesCtrHmacAeadTpmKey",
				"value": "IqgHIsUDEgQIEBAQ....",
				"keyMaterialType": "SYMMETRIC"
			},
			"status": "ENABLED",
			"keyId": 1643958734,
			"outputPrefixType": "TINK"
		}
	]
}
```

Signing

```json
{
	"primaryKeyId": 623370012,
	"key": [
		{
			"keyData": {
				"typeUrl": "type.googleapis.com/github.salrashid123.tink-go-tpm.RsaSsaPkcs1PublicTpmKey",
				"value": "EgIIAxqA...",
				"keyMaterialType": "ASYMMETRIC_PUBLIC"
			},
			"status": "ENABLED",
			"keyId": 623370012,
			"outputPrefixType": "TINK"
		}
	]
}

{
	"primaryKeyId": 623370012,
	"key": [
		{
			"keyData": {
				"typeUrl": "type.googleapis.com/github.salrashid123.tink-go-tpm.RsaSsaPkcs1PrivateTpmKey",
				"value": "EAIy1ggSjA...",
				"keyMaterialType": "ASYMMETRIC_PRIVATE"
			},
			"status": "ENABLED",
			"keyId": 623370012,
			"outputPrefixType": "TINK"
		}
	]
}
```


Where the "Value" field is the proto keys shown in `proto/tinktpm.proto`

#### Parent Key

Parent key is always using the [H-2 Template](https://github.com/salrashid123/tpm2/tree/master/h2_primary_template):

```bash
printf '\x00\x00' > unique.dat
tpm2_createprimary -C o -G ecc  -g sha256  -c primary.ctx -a "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda|restricted|decrypt" -u unique.dat
```

Though there isn't a way to specify the 'parent' password with this template, its good enough for now.

A todo is to support other templates and parent authorizations.

---

Also see

* [Simple Examples of using Tink Encryption library in Golang](https://github.com/salrashid123/tink_samples)
* [Export and Import external keys for TINK crypto](https://github.com/salrashid123/tink-keyset-util)


### Test

Due to the limitation of the singleton keymanager auth call back configs, each test must be run indipendently (i.,e you can run `go test -v ./...`)

```bash
## hmac tests
go test -v ./mac -run ^TestMac$
go test -v ./mac -run ^TestMacFail$

go test -v ./mac -run ^TestMacPassword$
go test -v ./mac -run ^TestMacPasswordFail$

go test -v ./mac -run ^TestMacPCR$
go test -v ./mac -run ^TestMacPCRFail$

go test -v ./mac -run ^TestMacOwnerPassword$
go test -v ./mac -run ^TestMacOwnerPasswordFail$


### aead tests

go test -v ./aead -run ^TestAead$
go test -v ./aead -run ^TestAeadFail$

go test -v ./aead -run ^TestAeadPassword$
go test -v ./aead -run ^TestAeadPasswordFail$

go test -v ./aead -run ^TestAeadPCR$
go test -v ./aead -run ^TestAeadPCRFail$

go test -v ./aead -run ^TestAeadOwnerPassword$
go test -v ./aead -run ^TestAeadOwnerPasswordFail$

### rsa tests

go test -v ./signature -run ^TestSignVerify$
go test -v ./signature -run ^TestSignVerifyFail$
```
