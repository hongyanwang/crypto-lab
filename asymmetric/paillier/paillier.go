// Package paillier implements Paillier homomorphic encryption
package paillier

import (
	"crypto/rand"
	"errors"
	"math/big"
	"strings"
)

var one = big.NewInt(1)
var zero = big.NewInt(0)

// PrivateKey represents a Paillier private key
type PrivateKey struct {
	PublicKey
	P      *big.Int // P is prime
	Q      *big.Int // Q is prime, P and Q have same length
	PP     *big.Int // P^2
	QQ     *big.Int // Q^2
	PinvQ  *big.Int // P^{-1} mod Q
	Lambda *big.Int // Lambda=(P-1)(Q-1)
	Mu     *big.Int // Mu=Lambda^-1 (mod N)
}

// PublicKey represents a Paillier public key
type PublicKey struct {
	N  *big.Int // N=P*Q
	G  *big.Int // G=N+1
	NN *big.Int // NN=N*N
}

// GenerateKey generates a paillier private key
func GenerateKey(secbit int) (*PrivateKey, error) {
	keylen := secbit / 2
	p, err := rand.Prime(rand.Reader, keylen)
	if err != nil {
		return nil, err
	}
	q, err := rand.Prime(rand.Reader, keylen)
	if err != nil {
		return nil, err
	}
	pp := new(big.Int).Mul(p, p)
	qq := new(big.Int).Mul(q, q)
	pinvq := new(big.Int).ModInverse(p, q)
	n := new(big.Int).Mul(p, q)
	nn := new(big.Int).Mul(n, n)
	lambda := new(big.Int).Mul(new(big.Int).Sub(p, one), new(big.Int).Sub(q, one))
	mu := new(big.Int).ModInverse(lambda, n)
	g := new(big.Int).Add(n, one)
	return &PrivateKey{
		PublicKey: PublicKey{
			N:  n,
			G:  g,
			NN: nn,
		},
		P:      p,
		Q:      q,
		PP:     pp,
		QQ:     qq,
		PinvQ:  pinvq,
		Lambda: lambda,
		Mu:     mu,
	}, nil
}

// Encrypt encrypt message using public key
// c=G^m*r^N (mod N^2)
func Encrypt(m *big.Int, pubkey *PublicKey) (*big.Int, error) {
	r, err := rand.Int(rand.Reader, pubkey.N)
	if err != nil {
		return nil, err
	}
	if new(big.Int).Mod(pubkey.N, r).Cmp(zero) == 0 {
		return nil, errors.New("encrypt error: improper random number")
	}
	gm := new(big.Int).Exp(pubkey.G, m, pubkey.NN)
	rn := new(big.Int).Exp(r, pubkey.N, pubkey.NN)
	return new(big.Int).Mod(new(big.Int).Mul(gm, rn), pubkey.NN), nil
}

// DecryptOrig decrypt message using private key
// m=L(c^Lambda mod N^2)*Mu (mod N)
func DecryptOrig(c *big.Int, prvkey *PrivateKey) (*big.Int, error) {
	nn := prvkey.PublicKey.NN
	if c.Cmp(nn) >= 0 {
		return nil, errors.New("ciphertext must be smaller than n square")
	}
	clambda := new(big.Int).Exp(c, prvkey.Lambda, nn)
	lc := L(clambda, prvkey.PublicKey.N)
	lcn := new(big.Int).Mod(lc, prvkey.N)
	lmu := new(big.Int).Mul(lcn, prvkey.Mu)
	return new(big.Int).Mod(lmu, prvkey.N), nil
}

// Decrypt optimization of decryption using CRT
// reference: [Paillier99, section 7](http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.112.4035&rep=rep1&type=pdf)
func Decrypt(c *big.Int, prvkey *PrivateKey) (*big.Int, error) {
	if c.Cmp(prvkey.NN) >= 0 {
		return nil, errors.New("ciphertext must be smaller than n square")
	}
	p1 := new(big.Int).Sub(prvkey.P, one)
	cp := new(big.Int).Exp(c, p1, prvkey.PP)
	lp := L(cp, prvkey.P)

	gp := new(big.Int).Mod(new(big.Int).Sub(one, prvkey.N), prvkey.PP)
	llp := L(gp, prvkey.P)
	hp := new(big.Int).ModInverse(llp, prvkey.P)
	a1 := new(big.Int).Mod(new(big.Int).Mul(lp, hp), prvkey.P)

	q1 := new(big.Int).Sub(prvkey.Q, one)
	cq := new(big.Int).Exp(c, q1, prvkey.QQ)
	lq := L(cq, prvkey.Q)

	gq := new(big.Int).Mod(new(big.Int).Sub(one, prvkey.N), prvkey.QQ)
	llq := L(gq, prvkey.Q)
	hq := new(big.Int).ModInverse(llq, prvkey.Q)
	a2 := new(big.Int).Mod(new(big.Int).Mul(lq, hq), prvkey.Q)
	return CRT(a1, a2, prvkey), nil
}

// L(x, n) = (x-1)/n
func L(x *big.Int, n *big.Int) *big.Int {
	return new(big.Int).Div(new(big.Int).Sub(x, one), n)
}

// Chinese remainder theorem
// m = a_1 + (a_2 - a_1)P^{-1}modQ * P (mod N)
func CRT(a1, a2 *big.Int, prvkey *PrivateKey) *big.Int {
	dif := new(big.Int).Sub(a2, a1)
	difP := new(big.Int).Mod(new(big.Int).Mul(dif, prvkey.PinvQ), prvkey.Q)
	difPP := new(big.Int).Mul(difP, prvkey.P)
	return new(big.Int).Mod(new(big.Int).Add(a1, difPP), prvkey.N)
}

// Add multiply two ciphertext to get encryption of the addition of two numbers
// enc(c1) * enc(c2) = enc(c1+c2)
func Add(cipher1, cipher2 *big.Int, pubkey *PublicKey) *big.Int {
	return new(big.Int).Mod(new(big.Int).Mul(cipher1, cipher2), pubkey.NN)
}

// ScalarMul exponent of ciphertext is encryption of the scalar multiplication of a number
// enc(s*c) = enc(c)^s
func ScalarMul(cipher, scalar *big.Int, pubkey *PublicKey) *big.Int {
	return new(big.Int).Exp(cipher, scalar, pubkey.NN)
}

// PrivateToString export private key to string
func PrivateToString(key *PrivateKey) string {
	return key.P.String() + "," + key.Q.String()
}

// PrivateFromString import private key from string
func PrivateFromString(data string) *PrivateKey {
	prvkey := strings.Split(data, ",")
	p, _ := new(big.Int).SetString(prvkey[0], 10)
	q, _ := new(big.Int).SetString(prvkey[1], 10)
	pp := new(big.Int).Mul(p, p)
	qq := new(big.Int).Mul(q, q)
	pinvq := new(big.Int).ModInverse(p, q)
	n := new(big.Int).Mul(p, q)
	nn := new(big.Int).Mul(n, n)
	lambda := new(big.Int).Mul(new(big.Int).Sub(p, one), new(big.Int).Sub(q, one))
	mu := new(big.Int).ModInverse(lambda, n)
	g := new(big.Int).Add(n, one)
	return &PrivateKey{
		PublicKey: PublicKey{
			N:  n,
			G:  g,
			NN: nn,
		},
		P:      p,
		Q:      q,
		PP:     pp,
		QQ:     qq,
		PinvQ:  pinvq,
		Lambda: lambda,
		Mu:     mu,
	}
}

// PublicToString export public key to string
func PublicToString(key *PublicKey) string {
	return key.N.String()
}

// PublicFromString import public key from string
func PublicFromString(data string) *PublicKey {
	n, _ := new(big.Int).SetString(data, 10)
	g := new(big.Int).Add(n, one)
	nn := new(big.Int).Mul(n, n)
	return &PublicKey{
		N:  n,
		G:  g,
		NN: nn,
	}
}
