package ecies

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/elliptic"
	"crypto/sha256"
	"hash"
)

var (
	DefaultCurve  = elliptic.P256()
	DefaultParams = ECIES_AES128_SHA256
)

type ECIESParams struct {
	Hash      func() hash.Hash
	hashAlgo  crypto.Hash
	Cipher    func([]byte) (cipher.Block, error)
	BlockSize int
	KeyLen    int
}

var (
	ECIES_AES128_SHA256 = &ECIESParams{
		Hash:      sha256.New,
		hashAlgo:  crypto.SHA256,
		Cipher:    aes.NewCipher,
		BlockSize: aes.BlockSize,
		KeyLen:    16,
	}
)
