# TINK Go TPM extension 


An encryption library for [Google Tink](https://github.com/google/tink) which uses Trusted Platform Modules (TPM) based key to perform operations.

Currently, while TINK itself supports a variety of [key types](https://developers.google.com/tink/supported-key-types), only the following are supported

* `HMAC`
  
>> NOTE: this repo is NOT supported by google and is very experimental

this is my own limited implementation of this FR: [issue #389](https://github.com/google/tink/issues/389)

### HMAC Example

The basic usage is pretty straightforward:

```golang
import (
	"github.com/google/go-tpm/tpm2"
	tinktpm "github.com/salrashid123/tink-go-tpm/v2"
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
//  func tinkcommon.NewPasswordSession(rwr transport.TPM, password []byte, policyDigest []byte, sensitive []byte) (tinkcommon.PasswordCallback, error)

	se, err := tinkcommon.NewPasswordSession(rwr, nil, pgd.PolicyDigest.Buffer, nil)

// bind the session to the keymanager (yeah, this isn't great but i coudn't figure out how to do this otherwise; see section at the end of the repo)
	hmacKeyManager := tinktpm.NewTPMHMACKeyManager(rwc, se)
	err = registry.RegisterKeyManager(hmacKeyManager)

// get a new  hmac key of any template type
	kh1, err := keyset.NewHandle(tinktpm.HMACSHA256Tag256KeyTPMTemplate())
	//kh1, err := keyset.NewHandle(tinktpm.HMACSHA256Tag256KeyTPMNoPrefixTemplate())
	//kh1, err := keyset.NewHandle(tinktpm.HMACSHA512Tag256KeyTPMTemplate())

// use the new key to compute a mac
	a, err := mac.New(kh1)
	tag, err := a.ComputeMAC([]byte("foo"))
	fmt.Printf("    MAC %s\n", base64.RawStdEncoding.EncodeToString(tag))
  ```

#### Basic

Test basic TPM based mac/verify without policy or password

If you want to use a software TPM to test with instead of a real one:

```bash
rm -rf /tmp/myvtpm && mkdir /tmp/myvtpm  && sudo swtpm socket --tpmstate dir=/tmp/myvtpm --tpm2 --server type=tcp,port=2321 --ctrl type=tcp,port=2322 --flags not-need-init,startup-clear

## then set the TPM flag in the examples to --tpm-path="127.0.0.1:2321"
```

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

### Policy AuthValue (password)

```bash
# create
$ go run hmac/password_policy/create/main.go \
   --tpm-path="127.0.0.1:2321" --password=testpswd --macFile=mac.dat \
   --plaintext=foo --keySet=keyset.json

2024/06/21 10:03:13     MAC AUHVQDso4qSDi2WAOAvKqg8suuxjZ4dXpgOdP4RppTOHbgW6zw

# verify
$ go run hmac/password_policy/verify/main.go \
   --tpm-path="127.0.0.1:2321" --password=testpswd --macFile=mac.dat \
   --plaintext=foo --keySet=keyset.json

2024/06/21 10:03:29 Verified   


### test with bad password
$ go run hmac/password_policy/verify/main.go \
   --tpm-path="127.0.0.1:2321" --password=wrongpswd --macFile=mac.dat \
   --plaintext=foo --keySet=keyset.json
2024/06/21 10:28:53 mac_factory: invalid mac
exit status 1

```

### Policy PCR 

To test with a PCR binding to pcr-23

```bash
# create
$ go run hmac/pcr_policy/create/main.go \
   --tpm-path="127.0.0.1:2321" --pcr=23 --macFile=mac.dat \
   --plaintext=foo --keySet=keyset.json

2024/06/21 10:03:13     MAC AUHVQDso4qSDi2WAOAvKqg8suuxjZ4dXpgOdP4RppTOHbgW6zw

# verify
$ go run hmac/pcr_policy/verify/main.go \
   --tpm-path="127.0.0.1:2321" --pcr=23 --macFile=mac.dat \
   --plaintext=foo --keySet=keyset.json

2024/06/21 10:03:29 Verified   
```

now test with an invalid pcr binding.  The error below indicates that the policy digest the key was initially created with (as encoded into the key (see `tinktpm.proto`)) does not match what was calculated in the session callback.  Even if this check was bypassed, the hmac would fail since the key itself on the TPM requires a specific PCR value

```bash
# if using software TPM:
# export TPM2TOOLS_TCTI="swtpm:port=2321"
$ tpm2_pcrread sha256:23
  sha256:
    23: 0x0000000000000000000000000000000000000000000000000000000000000000

## to mutate the pcr value
$ tpm2_pcrextend 23:sha256=0x0000000000000000000000000000000000000000000000000000000000000000

$ tpm2_pcrread sha256:23
  sha256:
    23: 0xF5A5FD42D16A20302798EF6ED309979B43003D2320D9F0E8EA9831A92759FB4B

$ go run hmac/pcr_policy/verify/main.go \
   --tpm-path="127.0.0.1:2321" --pcr=23 --macFile=mac.dat \
   --plaintext=foo --keySet=keyset.json

2024/06/21 10:31:45 mac_factory: cannot obtain primitive set: registry.PrimitivesWithKeyManager: cannot get primitive from key: error creating key: policy digest mismatch in key 3c87a4b3fb85ebeea58c5fb36ac22d3f280cec27a9f6dd0fa23be9ce560deec8, in session: 2094289099c2cb180f28f99c71c8d681123935f7330bdae5aa1ae1e09f0fe532
exit status 1

```

### With Sensitive

If you want to specify the MAC secret key, you can set the 'sensitive' part directly

```bash
# create
$ go run hmac/withsensitive/create/main.go \
   --tpm-path="127.0.0.1:2321" --sensitive="change this password to a secret" --macFile=mac.dat \
   --plaintext=foo --keySet=keyset.json

2024/06/21 10:37:43     MAC 7c50506d993b4a10e5ae6b33ca951bf2b8c8ac399e0a34026bb0ac469bea3de2

# verify
$ go run hmac/withsensitive/verify/main.go \
   --tpm-path="127.0.0.1:2321" --macFile=mac.dat \
   --plaintext=foo --keySet=keyset.json

2024/06/21 10:37:59 Verified
```

the example above performs a hmac which results in a given output since we specified the key:

eg

```bash
$ echo -n "change this password to a secret" | xxd -p -c 100
    6368616e676520746869732070617373776f726420746f206120736563726574

$ echo -n foo > data.in

$ openssl dgst -sha256 -mac hmac -macopt hexkey:6368616e676520746869732070617373776f726420746f206120736563726574 data.in
       HMAC-SHA256(data.in)= 7c50506d993b4a10e5ae6b33ca951bf2b8c8ac399e0a34026bb0ac469bea3de2
```

We specified the "no prefix" template (`HMACSHA256Tag256KeyTPMNoPrefixTemplate`) so to get the raw value.

---

### KeyManager Policy Callback

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

	kh1, err := keyset.NewHandle(tinktpm.HMACSHA256Tag256KeyTPMNoPrefixTemplate())
```

this limitation maynot be a big deal but it does cause issues if you attempt to create multiple hmac keys with different policies.


### Key Type

While the key type used here is custom: `"type.googleapis.com/github.salrashid123.tink-go-tpm.TPMHmacKey"`, you can still  use `tinkkey` for listing specifications (you can't use it to generate a new key since tinkey doens't know about this type...)


```bash
$ tinkey list-keyset --in keyset.json 

primary_key_id: 4093617498
key_info {
  type_url: "type.googleapis.com/github.salrashid123.tink-go-tpm.TPMHmacKey"
  status: ENABLED
  key_id: 4093617498
  output_prefix_type: TINK
}
```

In json format, the keyset looks like:

```bash
$ cat keyset.json  | jq '.'
{
  "primaryKeyId": 4093617498,
  "key": [
    {
      "keyData": {
        "typeUrl": "type.googleapis.com/github.salrashid123.tink-go-tpm.TPMHmacKey",
        "value": "EAEanwISUAAIAAsABAByACCPzSFpq5JpTgxjPxq3coQrgkG7wgKImB/HrB7dwf3bDgAFAAsAIIJNXu5tNBFSFGLkUM7FebVaiRsuVlmdbT1HfhP9KGPBGp4BACDIeM1Utmg2gGAK25eJ0yrgdM23YY6UgJZCMYx2K2OfpQAQLLEPcvd7JnTNBQURDBt+1aJTn0G6YTplUNiFa6AhA4VG2ySnP8A+EY3Kxm5X/3iUTAPxAoKwuEarVvEnDMYZ1uhn9PCzREJt/XjaPUFu/dcevUTs5iXOWc7v4vh/dtZUT2uDVmztb8j/3hfFG2W/jRXdiqnJSWsBBQ8iII/NIWmrkmlODGM/GrdyhCuCQbvCAoiYH8esHt3B/dsOKggKBAgDECAQIA==",
        "keyMaterialType": "SYMMETRIC"
      },
      "status": "ENABLED",
      "keyId": 4093617498,
      "outputPrefixType": "TINK"
    }
  ]
}
```

where the `value` is the encoded `HMACKey` proto:

```proto
message HMACKey {
  bytes name = 1;
  bytes public = 2;
  bytes private = 3;  
  bytes policy_digest = 4;  
  HMACKeyFormat key_format = 5;
}
```

which as json includes the public, private and the policydigest it was encoded with:

```json
{
  "public": "AAgACwAEAHIAII/NIWmrkmlODGM/GrdyhCuCQbvCAoiYH8esHt3B/dsOAAUACwAgnG2ZQnABLtY4vr2CJSvgOWNj2C2YGSBsLxwm03fz2Js=",
  "private": "ACCMoZ6bHt3+2pZPXWXiB+tHo5eH/HB15vDz/mQ3BYBINgAQNZ//X+6xhQHrilarvRTnT8URf2aYHphJISrGRnwF7/1dpIsQ4BvTJBeL96irwquR8swyz1mnF68Ks99sIdK87tgSs5z9TGvUMbdVJ5D6hgSbr2oLJabryCz/k+2a7NsfCf1Mw+bPZfb2FHYwMJU4MHIWwUwUkjube4c=",
  "policyDigest": "j80haauSaU4MYz8at3KEK4JBu8ICiJgfx6we3cH92w4=",
  "keyFormat": {
    "params": {
      "hash": "SHA256",
      "tagSize": 32
    },
    "keySize": 32
  }
}
```

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

