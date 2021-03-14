package sm2

import (
	"math/big"
)

var (
	zero = big.NewInt(0)
	one  = big.NewInt(1)
)

// PrivateKey SM2 private key
type PrivateKey struct {
	PublicKey
	D *big.Int
}

// PublicKey SM2 public key
type PublicKey struct {
	X, Y *big.Int
}

// Signature SM2 signature
type Signature struct {
	R, S *big.Int
}
