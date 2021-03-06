package aes

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"fmt"
)

func Encrypt(msg, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	blockSize := block.BlockSize()
	msg = padding(msg, blockSize)
	ciphertext := make([]byte, len(msg))

	mode := cipher.NewCBCEncrypter(block, key[:blockSize])
	mode.CryptBlocks(ciphertext, msg)

	return ciphertext, nil
}

func Decrypt(ciphertext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	plaintext := make([]byte, len(ciphertext))
	blockSize := block.BlockSize()

	blockMode := cipher.NewCBCDecrypter(block, key[:blockSize])
	blockMode.CryptBlocks(plaintext, ciphertext)

	return unpadding(plaintext)
}

func padding(src []byte, blocksize int) []byte {
	padnum := blocksize - len(src)%blocksize
	pad := bytes.Repeat([]byte{byte(padnum)}, padnum)
	return append(src, pad...)
}

func unpadding(src []byte) ([]byte, error) {
	n := len(src)
	unpadnum := int(src[n-1])

	if n < unpadnum {
		return nil, fmt.Errorf("invalid content")
	}
	return src[:n-unpadnum], nil
}
