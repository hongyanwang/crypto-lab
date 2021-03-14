package sm2

import (
	"crypto/elliptic"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"math/big"

	"github.com/hongyanwang/crypto-lab/hash/sm3"
)

// GenerateKey generate random key pair
func GenerateKey() (*PrivateKey, error) {
	curve := P256Sm2()
	d, x, y, err := elliptic.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, err
	}
	return &PrivateKey{
		PublicKey: PublicKey{
			X: x,
			Y: y,
		},
		D: new(big.Int).SetBytes(d),
	}, nil
}

// SM2Sign SM2 sign
func SM2Sign(msg []byte, privkey *PrivateKey, id []byte) (Signature, error) {
	curve := P256Sm2()
	m := ZA(privkey.PublicKey, id)
	m = append(m, msg...)
	e := sm3.SM3(m)
	eInt := new(big.Int).SetBytes(e)

	k, r, s := new(big.Int), new(big.Int), new(big.Int)
	var err error
	for {
		n1 := new(big.Int).Sub(sm2P256.N, one)
		k, err = rand.Int(rand.Reader, n1)
		if err != nil {
			return Signature{}, err
		}
		k = k.Add(k, one)
		x, _ := curve.ScalarBaseMult(k.Bytes())
		r = new(big.Int).Add(eInt, x)
		r = new(big.Int).Mod(r, sm2P256.N)
		if r.Cmp(zero) == 0 || new(big.Int).Add(r, k).Cmp(sm2P256.N) == 0 {
			continue
		}

		d1 := new(big.Int).Add(one, privkey.D)
		d1 = new(big.Int).ModInverse(d1, sm2P256.N)
		rd := new(big.Int).Mul(r, privkey.D)
		krd := new(big.Int).Sub(k, rd)
		mul := new(big.Int).Mul(d1, krd)
		s = new(big.Int).Mod(mul, sm2P256.N)
		if s.Cmp(zero) == 0 {
			continue
		}
		break
	}

	return Signature{
		R: r,
		S: s,
	}, nil
}

// SM2Verify verify SM2 signature
func SM2Verify(msg []byte, sig Signature, pubkey PublicKey, id []byte) (bool, error) {
	curve := P256Sm2()
	// r,s must in [1, n-1]
	if sig.R.Cmp(one) == -1 || sig.R.Cmp(sm2P256.N) >= 0 {
		return false, fmt.Errorf("wrong signature, r should between 1 and N-1")
	}
	if sig.S.Cmp(one) == -1 || sig.S.Cmp(sm2P256.N) >= 0 {
		return false, fmt.Errorf("wrong signature, s should between 1 and N-1")
	}

	m := ZA(pubkey, id)
	m = append(m, msg...)
	e := sm3.SM3(m)
	eInt := new(big.Int).SetBytes(e)
	t := new(big.Int).Add(sig.R, sig.S)
	t = new(big.Int).Mod(t, sm2P256.N)
	if t.Cmp(zero) == 0 {
		return false, nil
	}

	sGx, sGy := curve.ScalarBaseMult(sig.S.Bytes())
	tPx, tpy := curve.ScalarMult(pubkey.X, pubkey.Y, t.Bytes())
	x, _ := curve.Add(sGx, sGy, tPx, tpy)

	R := new(big.Int).Add(x, eInt)
	R = new(big.Int).Mod(R, sm2P256.N)
	if R.Cmp(sig.R) == 0 {
		return true, nil
	}
	return false, nil
}

// SM2Encrypt
func SM2Encrypt(msg []byte, pubkey *PublicKey) ([]byte, error) {
	return nil, nil
}

// SM2Decrypt
func SM2Decrypt(cipher []byte, privkey *PrivateKey) ([]byte, error) {
	return nil, nil
}

// ZA prepare for signature
// sm3(ENTLA, id, a, b, x, y)
func ZA(pubkey PublicKey, id []byte) []byte {
	msg := make([]byte, 4)
	binary.BigEndian.PutUint32(msg, uint32(len(id)))
	msg = append(msg, id...)
	msg = append(msg, sm2P256ToBig(&sm2P256.a).Bytes()...)
	msg = append(msg, sm2P256ToBig(&sm2P256.b).Bytes()...)
	msg = append(msg, pubkey.X.Bytes()...)
	msg = append(msg, pubkey.Y.Bytes()...)
	return sm3.SM3(msg)
}
