package ecies

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"testing"
)

func TestEcies(t *testing.T) {
	msg := []byte("ecies test msg")
	prv1, err := GenerateKey(rand.Reader, DefaultCurve, nil)
	if err != nil {
		fmt.Println(err.Error())
		t.FailNow()
	}

	ct, err := Encrypt(rand.Reader, &prv1.PublicKey, msg)
	if err != nil {
		t.Error(err)
	}

	pt, err := prv1.Decrypt(ct)
	if err != nil {
		t.Error(err)
	}

	if !bytes.Equal(pt, msg) {
		t.Logf("ciphertext: %v", ct)
		t.Logf("plaintext: %v", pt)
		t.Errorf("ecies: plaintext doesn't match message")
	}
}
