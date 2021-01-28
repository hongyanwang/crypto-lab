package bfv

import (
	"errors"

	"github.com/ldsec/lattigo/v2/bfv"
)

// SetParams use idx to indicate default parameters
func SetParams(idx int, modulus uint64) *bfv.Parameters {
	params := bfv.DefaultParams[idx]
	if modulus != 0 {
		params.SetT(modulus)
	}
	return params
}

// GenKeyPair generate private/public key pair randomly based on params
func GenKeyPair(params *bfv.Parameters) (*bfv.SecretKey, *bfv.PublicKey) {
	keygen := bfv.NewKeyGenerator(params)
	return keygen.GenKeyPair()
}

// Encrypt encrypt a plaintext smaller than params.T()
func Encrypt(params *bfv.Parameters, pk *bfv.PublicKey, plain uint64) *bfv.Ciphertext {
	encryptor := bfv.NewEncryptorFromPk(params, pk)
	encoder := bfv.NewEncoder(params)
	plaintext := bfv.NewPlaintext(params)
	encoder.EncodeUint([]uint64{plain}, plaintext)
	ciphertext := encryptor.EncryptNew(plaintext)
	return ciphertext
}

// Decrypt decrypt a ciphertext
func Decrypt(params *bfv.Parameters, sk *bfv.SecretKey, cipher *bfv.Ciphertext) uint64 {
	decryptor := bfv.NewDecryptor(params, sk)
	encoder := bfv.NewEncoder(params)
	result := encoder.DecodeUintNew(decryptor.DecryptNew(cipher))
	return result[0]
}

// HomoAdd add two ciphertexts
func HomoAdd(params *bfv.Parameters, ciphers []*bfv.Ciphertext) (*bfv.Ciphertext, error) {
	evaluator := bfv.NewEvaluator(params)
	if len(ciphers) < 2 {
		return nil, errors.New("invalid ciphertexts length")
	}

	ret := evaluator.AddNew(ciphers[0], ciphers[1])
	for i := 2; i < len(ciphers); i++ {
		ret = evaluator.AddNew(ret, ciphers[i])
	}
	return ret, nil
}

// HomoMul multiply two ciphertexts
func HomoMul(params *bfv.Parameters, ciphers []*bfv.Ciphertext) (*bfv.Ciphertext, error) {
	evaluator := bfv.NewEvaluator(params)
	if len(ciphers) < 2 {
		return nil, errors.New("invalid ciphertexts length")
	}

	ret := evaluator.MulNew(ciphers[0], ciphers[1])
	for i := 2; i < len(ciphers); i++ {
		ret = evaluator.MulNew(ret, ciphers[i])
	}
	return ret, nil
}
