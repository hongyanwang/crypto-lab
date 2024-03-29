package paillier

import (
	"fmt"
	"math/big"
	"testing"
)

var (
	prvkeyStr     string
	prvkey        *PrivateKey
	secbit        = 4096
	plaintext1    = big.NewInt(25)
	plaintext2    = big.NewInt(12)
	ciphertext1   *big.Int
	ciphertext2   *big.Int
	ciphertextAdd *big.Int
	scalar        = big.NewInt(10)
	ciphertextMul *big.Int
)

func BenchmarkKeyGen(b *testing.B) {
	for i := 0; i < b.N; i++ {
		testKeyGen()
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
func BenchmarkAdd(b *testing.B) {
	for i := 0; i < b.N; i++ {
		testAdd()
	}
}
func BenchmarkMul(b *testing.B) {
	for i := 0; i < b.N; i++ {
		testMul()
	}
}

func testKeyGen() {
	prvkey, _ = GenerateKey(secbit)
}
func testEnc() {
	ciphertext1, _ = Encrypt(plaintext1, &prvkey.PublicKey)
	ciphertext2, _ = Encrypt(plaintext2, &prvkey.PublicKey)
}
func testDec() {
	Decrypt(ciphertext1, prvkey)
}
func testAdd() {
	Add(ciphertext1, ciphertext2, &prvkey.PublicKey)
}
func testMul() {
	ScalarMul(ciphertext1, scalar, &prvkey.PublicKey)
}

/////////////////////////////////////////////////////////////////////////
func TestKeyGen(t *testing.T) {
	private, err := GenerateKey(secbit)
	if err != nil {
		t.Error(err)
	}
	prvkeyStr = PrivateToString(private)
	prvkey = PrivateFromString(prvkeyStr)
	fmt.Printf("%s\n\n", prvkeyStr)
}

func TestEnc(t *testing.T) {
	ciphertext1, _ = Encrypt(plaintext1, &prvkey.PublicKey)
	ciphertext2, _ = Encrypt(plaintext2, &prvkey.PublicKey)
}

func TestDec(t *testing.T) {
	plain1, _ := DecryptOrig(ciphertext1, prvkey)
	plain2, _ := Decrypt(ciphertext2, prvkey)
	fmt.Println(plain1)
	fmt.Println(plain2)
	fmt.Println("")
}

func TestAdd(t *testing.T) {
	ciphertextAdd = Add(ciphertext1, ciphertext2, &prvkey.PublicKey)
	plainAdd, _ := Decrypt(ciphertextAdd, prvkey)
	fmt.Println(plainAdd)
}

func TestMul(t *testing.T) {
	ciphertextMul = ScalarMul(ciphertext1, scalar, &prvkey.PublicKey)
	plainMul, _ := Decrypt(ciphertextMul, prvkey)
	fmt.Println(plainMul)
}
