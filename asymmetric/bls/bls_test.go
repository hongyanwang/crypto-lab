package bls

import (
	"testing"

	bls12_381_ecc "github.com/consensys/gnark-crypto/ecc/bls12-381"
)

var (
	prvkey *PrivateKey
	pubkey *PublicKey
	sig    = new(bls12_381_ecc.G1Affine)

	msg = []byte("test bls")
)

func TestBls(t *testing.T) {
	var err error
	prvkey, pubkey, err = GenRandomKeyPair()
	if err != nil {
		t.Error(err)
	}

	sig = Sign(prvkey, msg)
	v, err := Verify(sig, pubkey, msg)
	if err != nil {
		t.Error(err)
	}
	if !v {
		t.Errorf("BSL test failed")
	}
}

func BenchmarkKeyGen(b *testing.B) {
	for i := 0; i < b.N; i++ {
		prvkey, pubkey, _ = GenRandomKeyPair()
	}
}

func BenchmarkSign(b *testing.B) {
	for i := 0; i < b.N; i++ {
		sig = Sign(prvkey, msg)
	}
}

func BenchmarkVerify(b *testing.B) {
	for i := 0; i < b.N; i++ {
		Verify(sig, pubkey, msg)
	}
}
