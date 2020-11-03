package rsa

import (
	"crypto/rand"
	"errors"
	"math/big"
)

var one = big.NewInt(1)
var zero = big.NewInt(0)

// PrivateKey represents a RSAA private key
type PrivateKey struct {
	PublicKey
	P			*big.Int	// P and Q are primes with same length
	Q			*big.Int
	N			*big.Int	// N=P*Q
	Phi			*big.Int	// Phi=(P-1)(Q-1)
	D			*big.Int	// D = e^-1 (mod phi)
}

// PublicKey represents a Paillier public key
type PublicKey struct {
	N        *big.Int	// N=P*Q
	E        *big.Int	// 0 < E < phi，&& e and phi are coprime
}

// GenerateKey generates a rsa private key
func GenerateKey(secbit int) (*PrivateKey, error) {
	keylen := secbit/2
	p, err := rand.Prime(rand.Reader, keylen)
	if err != nil {
		return nil, err
	}
	q, err := rand.Prime(rand.Reader, keylen)
	if err != nil {
		return nil, err
	}
	n := new(big.Int).Mul(p,q)
	phi := new(big.Int).Mul(new(big.Int).Sub(p, one), new(big.Int).Sub(q, one))
	// e cannot be zero, e and phi must be coprime
	var e *big.Int
	for {
		e, err = rand.Int(rand.Reader, phi)
		if err != nil {
			return nil, err
		}
		gcd := new(big.Int).GCD(nil, nil, e, phi)
		if e.Cmp(zero) != 0 && gcd.Cmp(one) == 0 {
			break
		}
	}
	d := new(big.Int).ModInverse(e, phi)
	return &PrivateKey{
		PublicKey: PublicKey{
			N:        n,
			E:        e,
		},
		P: p,
		Q: q,
		N: n,
		Phi: phi,
		D: d,
	}, nil
}

// RSA encryption and decryption
// ciphertext = m^E (mod N)
func RSAEncrypt(m *big.Int, pubkey *PublicKey) (*big.Int, error) {
	if m.Cmp(pubkey.N) > 0 {
		return nil, errors.New("message must be smaller than N")
	}
	c := new(big.Int).Exp(m, pubkey.E, pubkey.N)
	return c, nil
}

// plaintext = cipher^D (mod N)
func RSADecrypt(c *big.Int, prvkey *PrivateKey) (*big.Int, error) {
	if c.Cmp(prvkey.N) > 0 {
		return nil, errors.New("message must be smaller than N")
	}
	m := new(big.Int).Exp(c, prvkey.D, prvkey.N)
	return m, nil
}

// homomorphic encryption
func RSAMul(cipher1, cipher2 *big.Int, pubkey *PublicKey) *big.Int {
	return new(big.Int).Mod(new(big.Int).Mul(cipher1,cipher2), pubkey.N)
}

// signature and verification
// sig = m^D (mod N)
func RSASign(m *big.Int, prvkey *PrivateKey) (*big.Int, error) {
	if m.Cmp(prvkey.N) > 0 {
		return nil, errors.New("message must be smaller than N")
	}
	sig := new(big.Int).Exp(m, prvkey.D, prvkey.N)
	return sig, nil
}

// msg = sig^E (mod N)
func RSAVerify(m *big.Int, sig *big.Int, pubkey *PublicKey) (bool, error) {
	if m.Cmp(pubkey.N) > 0 {
		return false, errors.New("message must be smaller than N")
	}
	if sig.Cmp(pubkey.N) > 0 {
		return false, errors.New("signature must be smaller than N")
	}
	mm := new(big.Int).Exp(sig, pubkey.E, pubkey.N)
	if mm.Cmp(m) == 0 {
		return true, nil
	}
	return false, nil
}

