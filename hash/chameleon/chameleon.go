package chameleon

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"math/big"
)

var DefaultCurveType = elliptic.P256()

// ChamHash input message and random r, output hash
func ChamHash(msg, r *big.Int, pk *ecdsa.PublicKey) *ecdsa.PublicKey {
	x1, y1 := DefaultCurveType.ScalarBaseMult(msg.Bytes())
	x2, y2 := DefaultCurveType.ScalarMult(pk.X, pk.Y, r.Bytes())
	x, y := DefaultCurveType.Add(x1, y1, x2, y2)
	return &ecdsa.PublicKey{
		Curve: DefaultCurveType,
		X:     x,
		Y:     y,
	}
}

// FindCollisionR given M' and r, find r' such that hash(M',r')=hash(M,r)
func FindCollisionR(msg, newMsg, r, sk *big.Int) *big.Int {
	m := msg.Sub(msg, newMsg)
	rx := r.Mul(r, sk)
	mrx := m.Add(m, rx)
	mrx = mrx.Mod(mrx, DefaultCurveType.Params().N)
	xInv := sk.ModInverse(sk, DefaultCurveType.Params().N)
	return mrx.Mul(mrx, xInv)
}
