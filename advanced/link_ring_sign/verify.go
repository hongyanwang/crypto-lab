package link_ring_sign

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"math/big"
)

// verify
func verify(sig, msg []byte) (bool, error) {
	var ringSign LinkRingSignature
	if err := json.Unmarshal(sig, &ringSign); err != nil {
		return false, fmt.Errorf("failed to unmarshal signature, err: %v", err)
	}

	if err := checkSignature(ringSign); err != nil {
		return false, err
	}

	// compute E1
	e := ringSign.E1
	minN := minN(ringSign.PublicKeys)
	// E_{i+1} = hash(s*hash(P_i)+E_i*linkKey+m)
	for i := 0; i < len(ringSign.PublicKeys); i++ {
		hashPi := sha256.Sum256(ringSign.PublicKeys[i].E.Bytes())
		sHashPi := new(big.Int).Mul(ringSign.Ss[i], new(big.Int).SetBytes(hashPi[:]))
		eiLink := new(big.Int).Mul(e, ringSign.LinkKey)
		add := new(big.Int).Add(sHashPi, eiLink)
		add = add.Add(add, new(big.Int).SetBytes(msg))
		add = add.Mod(add, minN)
		eb := sha256.Sum256(add.Bytes())
		e = new(big.Int).SetBytes(eb[:])
	}

	if ringSign.E1.Cmp(e) != 0 {
		return false, nil
	}
	return true, nil
}

// checkSignature check if signature is valid
func checkSignature(sig LinkRingSignature) error {
	if sig.E1 == nil {
		return fmt.Errorf("invalid signature, nil E1")
	}
	if sig.Ss == nil {
		return fmt.Errorf("invalid signature, nil Ss")
	}
	if sig.PublicKeys == nil {
		return fmt.Errorf("invalid signature, nil public keys")
	}
	if sig.LinkKey == nil {
		return fmt.Errorf("invalid signature, nil link key")
	}
	if len(sig.Ss) != len(sig.PublicKeys) {
		return fmt.Errorf("invalid signature, public keys and Ss should have same length")
	}
	return nil
}
