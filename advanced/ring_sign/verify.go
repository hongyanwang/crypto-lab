package ring_sign

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"math/big"
)

// verify
func verify(sig, msg []byte) (bool, error) {
	var ringSign RingSignature
	if err := json.Unmarshal(sig, &ringSign); err != nil {
		return false, fmt.Errorf("failed to unmarshal signature, err: %v", err)
	}

	if err := checkSignature(ringSign); err != nil {
		return false, err
	}

	key := sha256.Sum256(msg)
	c, err := cky(ringSign.PublicKeys, ringSign.Xs, key[:], ringSign.V)
	if err != nil {
		return false, fmt.Errorf("failed to compute cky, err: %v", err)
	}
	if new(big.Int).SetBytes(c).Cmp(ringSign.V) != 0 {
		return false, nil
	}
	return true, nil
}

// checkSignature check if signature is valid
func checkSignature(sig RingSignature) error {
	if sig.V == nil {
		return fmt.Errorf("invalid signature, nil v")
	}
	if sig.Xs == nil {
		return fmt.Errorf("invalid signature, nil xs")
	}
	if sig.PublicKeys == nil {
		return fmt.Errorf("invalid signature, nil public keys")
	}
	if len(sig.Xs) != len(sig.PublicKeys) {
		return fmt.Errorf("invalid signature, public keys and xs should have same length")
	}
	return nil
}
