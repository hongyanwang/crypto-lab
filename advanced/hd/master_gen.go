package hd

import (
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha512"
	"errors"
	"math/big"
)

var (
	// seed from [0, 2^128]
	secbits = new(big.Int).SetInt64(128)
	seedMax = new(big.Int).Exp(two, secbits, nil)

	masterHmacKey = "why seed"
)

// GenerateMaster generate a master private key with chain code
func GenerateMaster() (*HDPrivateKey, error) {
	seed, err := rand.Int(rand.Reader, seedMax)
	if err != nil {
		return nil, err
	}
	return GenerateMasterBySeed(seed)
}

// GenerateMasterBySeed generate a master private key with chain code by seed
func GenerateMasterBySeed(seed *big.Int) (*HDPrivateKey, error) {
	// I = hmac512(masterHmacKey, seed)
	hmac := hmac.New(sha512.New, []byte(masterHmacKey))
	I := hmac.Sum(seed.Bytes())
	Il, Ir := I[:32], I[32:]

	masterD := new(big.Int).SetBytes(Il)
	// if master key is 0 or greater than N, return invalid error
	if masterD.Cmp(zero) == 0 || masterD.Cmp(P256Curve.Params().N) == 1 {
		return nil, errors.New("master key is invalid")
	}

	x, y := P256Curve.ScalarBaseMult(Il)
	chaincode := new(big.Int).SetBytes(Ir)

	return &HDPrivateKey{
		Privkey: ecdsa.PrivateKey{
			PublicKey: ecdsa.PublicKey{
				Curve: P256Curve,
				X:     x,
				Y:     y,
			},
			D: masterD,
		},
		ChainCode: chaincode,
	}, nil
}
