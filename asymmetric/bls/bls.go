// Package bls implements BLS signature
package bls

import (
	"crypto/rand"
	"crypto/sha256"
	"math/big"

	bls12_381_ecc "github.com/consensys/gnark-crypto/ecc/bls12-381"
	bls12_381_fr "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

var (
	g1Gen bls12_381_ecc.G1Affine
	g2Gen bls12_381_ecc.G2Affine
	order *big.Int
)

func init() {
	_, _, g1Gen, g2Gen = bls12_381_ecc.Generators()
	order = bls12_381_fr.Modulus()
}

// PrivateKey client private key
type PrivateKey struct {
	X *big.Int
}

// PublicKey client public key
type PublicKey struct {
	P *bls12_381_ecc.G2Affine
}

// GenRandomKeyPair generate a random BLS private/public key pair for client
func GenRandomKeyPair() (*PrivateKey, *PublicKey, error) {
	sk, err := randomWithinOrder()
	if err != nil {
		return nil, nil, err
	}

	pk := new(bls12_381_ecc.G2Affine).ScalarMultiplication(&g2Gen, sk)

	privkey := &PrivateKey{
		X: sk,
	}
	pubkey := &PublicKey{
		P: pk,
	}
	return privkey, pubkey, nil
}

// Sign generate BLS signature using private key
// sig = sk * hashToG1(m)
func Sign(key *PrivateKey, msg []byte) *bls12_381_ecc.G1Affine {
	hash := sha256.Sum256(msg)
	g1 := hashToG1(hash[:])
	return new(bls12_381_ecc.G1Affine).ScalarMultiplication(g1, key.X)
}

// Verify verify BLS signature using public key
// e(sig, g_2)=e(hashToG1(m), pub)
func Verify(sig *bls12_381_ecc.G1Affine, pub *PublicKey, msg []byte) (bool, error) {
	left, err := bls12_381_ecc.Pair([]bls12_381_ecc.G1Affine{*sig}, []bls12_381_ecc.G2Affine{g2Gen})
	if err != nil {
		return false, err
	}
	hash := sha256.Sum256(msg)
	hashG1 := hashToG1(hash[:])
	right, err := bls12_381_ecc.Pair([]bls12_381_ecc.G1Affine{*hashG1}, []bls12_381_ecc.G2Affine{*pub.P})
	if err != nil {
		return false, err
	}
	if left.Equal(&right) {
		return true, nil
	}
	return false, nil
}

// randomWithinOrder generate a random number smaller than the order of G1/G2
func randomWithinOrder() (*big.Int, error) {
	return rand.Int(rand.Reader, order)
}

// hashToG1 define a hash function from big int to point in G1
func hashToG1(data []byte) *bls12_381_ecc.G1Affine {
	hash := sha256.Sum256(data)
	scalar := new(big.Int).SetBytes(hash[:])
	return new(bls12_381_ecc.G1Affine).ScalarMultiplication(&g1Gen, scalar)
}
