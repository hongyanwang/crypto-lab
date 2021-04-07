package ot

import (
	"bytes"
	"testing"
)

func TestOT(t *testing.T) {
	msgList := [][]byte{[]byte("hello"), []byte("world"), []byte("ot"), []byte("test")}
	target := 2

	privkey, randS, err := GenerateRandomSi(msgList)
	if err != nil {
		t.Error(err)
	}

	s, S, err := GenerateS(&privkey.PublicKey, randS, target)
	if err != nil {
		t.Error(err)
	}

	ps, err := ComputePi(msgList, randS, S, privkey)
	if err != nil {
		t.Error(err)
	}

	msg := RecoverM(ps, s, target)
	if !bytes.Equal(msgList[target], msg) {
		t.Logf("received message: %s\n", msg)
		t.Errorf("ot test failed")
	}
}
