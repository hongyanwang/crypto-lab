package bfv

import (
	"fmt"
	"testing"

	"github.com/ldsec/lattigo/v2/bfv"
)

func TestBFV(t *testing.T) {
	// plaintext modulus is 65929217
	params := SetParams(1, 0x3ee0001)

	sk, pk := GenKeyPair(params)

	plain1 := uint64(2048)
	plain2 := uint64(4096)

	cipher1 := Encrypt(params, pk, plain1)
	cipher2 := Encrypt(params, pk, plain2)

	cipherAdd, err := HomoAdd(params, []*bfv.Ciphertext{cipher1, cipher2})
	if err != nil {
		t.Error(err)
	}

	cipherMul, err := HomoMul(params, []*bfv.Ciphertext{cipher1, cipher2})
	if err != nil {
		t.Error(err)
	}

	decrypted1 := Decrypt(params, sk, cipher1)
	decrypted2 := Decrypt(params, sk, cipher2)
	decryptedAdd := Decrypt(params, sk, cipherAdd)
	decryptedMul := Decrypt(params, sk, cipherMul)

	if plain1 != decrypted1 {
		t.Errorf("plain1: %d, decrypted1: %d\n", plain1, decrypted1)
	}
	if plain2 != decrypted2 {
		fmt.Printf("plain2: %d, decrypted2: %d\n", plain2, decrypted2)
	}
	if plain1+plain2 != decryptedAdd {
		fmt.Printf("plainMul: %d, encryptedMul: %d\n", plain1+plain2, decryptedAdd)
	}
	if plain1*plain2 != decryptedMul {
		fmt.Printf("plainMul: %d, encryptedMul: %d\n", plain1*plain2, decryptedMul)
	}
}
