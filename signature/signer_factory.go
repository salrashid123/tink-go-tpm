package signature

import (
	"fmt"

	"github.com/tink-crypto/tink-go/v2/core/primitiveset"

	"github.com/tink-crypto/tink-go/v2/keyset"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
	"github.com/tink-crypto/tink-go/v2/tink"
)

// NewSigner returns a Signer primitive from the given keyset handle.
func NewSigner(handle *keyset.Handle) (tink.Signer, error) {
	ps, err := handle.Primitives()
	if err != nil {
		return nil, fmt.Errorf("public_key_sign_factory: cannot obtain primitive set: %s", err)
	}
	return newWrappedSigner(ps)
}

// wrappedSigner is an Signer implementation that uses the underlying primitive set for signing.
type wrappedSigner struct {
	ps *primitiveset.PrimitiveSet
}

// Asserts that wrappedSigner implements the Signer interface.
var _ tink.Signer = (*wrappedSigner)(nil)

func newWrappedSigner(ps *primitiveset.PrimitiveSet) (*wrappedSigner, error) {
	if _, ok := (ps.Primary.Primitive).(tink.Signer); !ok {
		return nil, fmt.Errorf("public_key_sign_factory: not a Signer primitive")
	}

	for _, primitives := range ps.Entries {
		for _, p := range primitives {
			if _, ok := (p.Primitive).(tink.Signer); !ok {
				return nil, fmt.Errorf("public_key_sign_factory: not an Signer primitive")
			}
		}
	}
	return &wrappedSigner{
		ps: ps,
	}, nil
}

// Sign signs the given data and returns the signature concatenated with the identifier of the
// primary primitive.
func (s *wrappedSigner) Sign(data []byte) ([]byte, error) {
	primary := s.ps.Primary
	signer, ok := (primary.Primitive).(tink.Signer)
	if !ok {
		return nil, fmt.Errorf("public_key_sign_factory: not a Signer primitive")
	}

	var signedData []byte
	if primary.PrefixType == tinkpb.OutputPrefixType_LEGACY {
		signedData = make([]byte, 0, len(data)+1)
		signedData = append(signedData, data...)
		signedData = append(signedData, byte(0))
	} else {
		signedData = data
	}

	signature, err := signer.Sign(signedData)
	if err != nil {
		//s.logger.LogFailure()
		return nil, err
	}

	output := make([]byte, 0, len(primary.Prefix)+len(signature))
	output = append(output, primary.Prefix...)
	output = append(output, signature...)
	return output, nil
}
