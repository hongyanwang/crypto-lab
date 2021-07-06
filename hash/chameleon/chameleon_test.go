package chameleon

import (
	"crypto/ecdsa"
	"crypto/rand"
	"math/big"
	"testing"
)

func TestChamHash(t *testing.T) {
	privkey, err := ecdsa.GenerateKey(DefaultCurveType, rand.Reader)
	if err != nil {
		t.Error(err)
	}

	msg := big.NewInt(123)
	r := big.NewInt(456)
	hash := ChamHash(msg, r, &privkey.PublicKey)

	newMsg := big.NewInt(789)
	newR := FindCollisionR(msg, newMsg, r, privkey.D)
	newHash := ChamHash(newMsg, newR, &privkey.PublicKey)

	if newHash.X.Cmp(hash.X) != 0 || newHash.X.Cmp(hash.X) != 0 {
		t.Errorf("TestChamHash failed")
	}
}
