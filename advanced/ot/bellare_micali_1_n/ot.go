package bellare_micali

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"math/big"
)

var (
	DefaultCurveType = elliptic.P256()

	minusOne = new(big.Int).SetInt64(-1)
)

// CipherM encrypted message structure
type CipherM struct {
	RG   *ecdsa.PublicKey
	EncM *big.Int
}

// ComputePKs compute public keys based on given c, return random k and PK0
// index is the index of target message
func ComputePKs(c *big.Int, index int) (*big.Int, *ecdsa.PublicKey, error) {
	// random k
	k, err := rand.Int(rand.Reader, DefaultCurveType.Params().N)
	if err != nil {
		return nil, nil, err
	}

	// pk_b = k*G
	x, y := DefaultCurveType.ScalarBaseMult(k.Bytes())

	// pk_i = k*G + (i-b)*c*G, pk_0 = k*G - b*c*G
	minusBC := new(big.Int).Mul(minusOne, big.NewInt(int64(index)))
	minusBC = minusBC.Mul(minusBC, c)
	minusBC = minusBC.Mod(minusBC, DefaultCurveType.Params().N)
	bcGx, bcGy := DefaultCurveType.ScalarBaseMult(minusBC.Bytes())
	pk0X, pk0Y := DefaultCurveType.Add(x, y, bcGx, bcGy)

	pk0 := &ecdsa.PublicKey{
		Curve: DefaultCurveType,
		X:     pk0X,
		Y:     pk0Y,
	}

	return k, pk0, nil
}

// ComputeCs compute cipherMs
func ComputeCs(c *big.Int, pk0 *ecdsa.PublicKey, ms []*big.Int) ([]CipherM, error) {
	// pk_i = pk_{i-1} + c*G
	cGx, cGy := DefaultCurveType.ScalarBaseMult(c.Bytes())
	pks := []*ecdsa.PublicKey{pk0}
	for i := 1; i < len(ms); i++ {
		x, y := DefaultCurveType.Add(pks[i-1].X, pks[i-1].Y, cGx, cGy)
		pk := &ecdsa.PublicKey{
			Curve: DefaultCurveType,
			X:     x,
			Y:     y,
		}
		pks = append(pks, pk)
	}

	// random {r_0, r_1 ... r_{n-1}}
	var rs []*big.Int
	for i := 0; i < len(ms); i++ {
		r, err := rand.Int(rand.Reader, DefaultCurveType.Params().N)
		if err != nil {
			return nil, err
		}
		rs = append(rs, r)
	}

	// compute {C_0, C_1 ... C_{n-1}}
	// C_i = [r_i*G, Hash(pk_i*r_i)+m_i]
	var cs []CipherM
	for i := 0; i < len(ms); i++ {
		rGx, rGy := DefaultCurveType.ScalarBaseMult(rs[i].Bytes())
		pkrX, pkrY := DefaultCurveType.ScalarMult(pks[i].X, pks[i].Y, rs[i].Bytes())
		hashPk := hashP(pkrX, pkrY)
		encM1 := new(big.Int).Add(hashPk, ms[i])

		c := CipherM{
			RG: &ecdsa.PublicKey{
				Curve: DefaultCurveType,
				X:     rGx,
				Y:     rGy,
			},
			EncM: encM1,
		}
		cs = append(cs, c)
	}

	return cs, nil
}

// RecoverM recover message from cs
func RecoverM(cs []CipherM, index int, k *big.Int) *big.Int {
	cipherM := cs[index]
	x, y := DefaultCurveType.ScalarMult(cipherM.RG.X, cipherM.RG.Y, k.Bytes())
	hash := hashP(x, y)
	m := new(big.Int).Sub(cipherM.EncM, hash)
	return m
}

// hashP hash ecdsa point to big int
func hashP(x, y *big.Int) *big.Int {
	content := append(x.Bytes(), y.Bytes()...)
	hash := sha256.Sum256(content)
	return new(big.Int).SetBytes(hash[:])
}
