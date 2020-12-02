package hd

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"math/big"
	"testing"
)

func TestKeyDerive(t *testing.T) {
	privkey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Errorf("failed to generate private key: %v\n", err)
	}

	code, err := rand.Int(rand.Reader, normalIndexMax)
	if err != nil {
		t.Errorf("failed to generate random number: %v\n", err)
	}

	parentPriv := &HDPrivateKey{
		Privkey:   *privkey,
		ChainCode: code,
	}
	parentPub := &HDPublicKey{
		PubKey:    privkey.PublicKey,
		ChainCode: code,
	}

	childPriv := PrivateToPrivate(parentPriv, two)
	childPub, err := PublicToPublic(parentPub, two)
	if err != nil {
		t.Errorf("failed to derive public child key: %v\n", err)
	}

	if childPriv.Privkey.X.Cmp(childPub.PubKey.X) != 0 || childPriv.Privkey.Y.Cmp(childPub.PubKey.Y) != 0 {
		t.Error("invalid derivation")
	}
}

func TestGenerateMaster(t *testing.T) {
	seed, v := new(big.Int).SetString("000102030405060708090a0b0c0d0e0f", 16)
	if !v {
		t.Error("failed to parse seed")
	}
	master, err := GenerateMasterBySeed(seed)
	if err != nil {
		t.Error(err)
	}

	t.Log(master)
}
