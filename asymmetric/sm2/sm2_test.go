package sm2

import (
	"testing"
)

func TestSM2(t *testing.T) {
	privkey, err := GenerateKey()
	if err != nil {
		t.Error(err)
	}

	msg := []byte("test")
	id := []byte("why")
	sig, err := SM2Sign(msg, privkey, id)
	if err != nil {
		t.Error(err)
	}

	v, err := SM2Verify(msg, sig, privkey.PublicKey, id)
	if err != nil {
		t.Error(err)
	}
	if !v {
		t.Errorf("verification failed")
	}
}
