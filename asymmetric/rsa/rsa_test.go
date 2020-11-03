package rsa

import (
	"fmt"
	"math/big"
	"testing"
)

var (
	secbit = 4096
	prvkey *PrivateKey
	plaintext1 = big.NewInt(25)
	plaintext2 = big.NewInt(12)
	ciphertext1 *big.Int
	ciphertext2 *big.Int
	ciphertextMul *big.Int
	signature *big.Int
)

func BenchmarkKeyGen(b *testing.B) {
	for i:=0;i<b.N;i++{
		testKeyGen()
	}
}
func BenchmarkEnc(b *testing.B) {
	for i:=0;i<b.N;i++{
		testEnc()
	}
}
func BenchmarkDec(b *testing.B) {
	for i:=0;i<b.N;i++{
		testDec()
	}
}
func BenchmarkMul(b *testing.B) {
	for i:=0;i<b.N;i++{
		testMul()
	}
}
func BenchmarkSig(b *testing.B) {
	for i:=0;i<b.N;i++{
		testSig()
	}
}
func BenchmarkVerify(b *testing.B) {
	for i:=0;i<b.N;i++{
		testVerify()
	}
}

func testKeyGen() {
	prvkey,_ = GenerateKey(secbit)
}
func testEnc() {
	ciphertext1,_ = RSAEncrypt(plaintext1, &prvkey.PublicKey)
	ciphertext2,_ = RSAEncrypt(plaintext2, &prvkey.PublicKey)
}
func testDec() {
	RSADecrypt(ciphertext1, prvkey)
	RSADecrypt(ciphertext2, prvkey)
}
func testMul() {
	RSAMul(ciphertext1, ciphertext2, &prvkey.PublicKey)
}
func testSig() {
	signature, _ = RSASign(plaintext1, prvkey)
}
func testVerify() {
	RSAVerify(plaintext1, signature, &prvkey.PublicKey)
}


func TestKeyGen(t *testing.T) {
	privateKey,err := GenerateKey(secbit)
	if err!= nil {
		t.Error(err)
	}
	prvkey = privateKey
	fmt.Println(prvkey)
}

func TestEnc(t *testing.T) {
	var err error
	ciphertext1,err = RSAEncrypt(plaintext1, &prvkey.PublicKey)
	if err != nil {
		t.Error(err)
	}
	ciphertext2,err = RSAEncrypt(plaintext2, &prvkey.PublicKey)
	if err != nil {
		t.Error(err)
	}
	fmt.Println(ciphertext1)
	fmt.Println(ciphertext2)
}

func TestDec(t *testing.T) {
	plain1,err := RSADecrypt(ciphertext1, prvkey)
	if err != nil {
		t.Error(err)
	}
	plain2,err := RSADecrypt(ciphertext2, prvkey)
	if err != nil {
		t.Error(err)
	}
	fmt.Println(plain1)
	fmt.Println(plain2)
}

func TestMul(t *testing.T) {
	ciphertextMul = RSAMul(ciphertext1, ciphertext2, &prvkey.PublicKey)
	plainMul,err := RSADecrypt(ciphertextMul, prvkey)
	if err != nil {
		t.Error(err)
	}
	fmt.Println(plainMul)
}

func TestSig(t *testing.T) {
	var err error
	signature,err = RSASign(plaintext1, prvkey)
	if err != nil {
		t.Error(err)
	}
	v,err := RSAVerify(plaintext1, signature, &prvkey.PublicKey)
	if err != nil {
		t.Error(err)
	}
	fmt.Println(v)
}
