package aes

import (
	"crypto/sha256"
	"reflect"
	"testing"
)

var (
	msg        = []byte("aes test msg")
	key        = sha256.Sum256([]byte("aes test key"))
	ciphertext []byte
)

func TestAES(t *testing.T) {
	ciphertext, err := Encrypt(msg, key[:])
	if err != nil {
		t.Error(err)
	}
	plaintext, err := Decrypt(ciphertext, key[:])
	if err != nil {
		t.Error(err)
	}
	if !reflect.DeepEqual(plaintext, msg) {
		t.Logf("msg: %v", msg)
		t.Logf("ciphertext: %v", ciphertext)
		t.Logf("plaintext: %v", plaintext)
		t.Errorf("aes encrypt/decrypt failed")
	}
}

func BenchmarkEnc(b *testing.B) {
	for i := 0; i < b.N; i++ {
		testEnc()
	}
}
func BenchmarkDec(b *testing.B) {
	for i := 0; i < b.N; i++ {
		testDec()
	}
}

func testEnc() {
	ciphertext, _ = Encrypt(msg, key[:])
}

func testDec() {
	Decrypt(ciphertext, key[:])
}
