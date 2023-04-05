package link_ring_sign

import (
	"testing"

	"github.com/hongyanwang/crypto-lab/asymmetric/rsa"
)

func TestRingSignature(t *testing.T) {
	msg := []byte("ring signature test msg")
	privkey1, err := rsa.GenerateKey(defaultSecbit)
	if err != nil {
		t.Error(err)
	}
	privkey2, err := rsa.GenerateKey(defaultSecbit)
	if err != nil {
		t.Error(err)
	}
	privkey3, err := rsa.GenerateKey(defaultSecbit)
	if err != nil {
		t.Error(err)
	}

	pubkeys := []*rsa.PublicKey{&privkey1.PublicKey, &privkey2.PublicKey}
	signature, err := Sign(pubkeys, privkey3, msg)
	if err != nil {
		t.Error(err)
	}

	// right message
	v, err := verify(signature, msg)
	if err != nil {
		t.Error(err)
	}
	if !v {
		t.Errorf("link ring signature test failed")
	}

	// wrong message
	v, err = verify(signature, []byte("wrong ring signature msg"))
	if err != nil {
		t.Error(err)
	}
	if v {
		t.Errorf("link ring signature supposed to be failed")
	}
}
