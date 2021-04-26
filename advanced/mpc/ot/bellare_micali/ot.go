package bellare_micali

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"
)

var (
	DefaultCurveType = elliptic.P256()
	DefaultMsgLen    = 2

	minusOne = new(big.Int).SetInt64(-1)
	// note: -P = (-1)*P = [(-1) mod N] * P
	minusOneModN = new(big.Int).ModInverse(minusOne, DefaultCurveType.Params().N)
)

// CipherM encrypted message structure
type CipherM struct {
	RG   *ecdsa.PublicKey
	EncM *big.Int
}

// ComputePKs compute public keys based on given c, return random k and PK0
func ComputePKs(c *big.Int, index int) (*big.Int, *ecdsa.PublicKey, error) {
	// random k
	k, err := rand.Int(rand.Reader, DefaultCurveType.Params().N)
	if err != nil {
		return nil, nil, err
	}

	// pkb = kG
	x, y := DefaultCurveType.ScalarBaseMult(k.Bytes())

	// pk_{1-b} = cG-pkb
	cGx, cGy := DefaultCurveType.ScalarBaseMult(c.Bytes())
	mx, my := DefaultCurveType.ScalarMult(x, y, minusOneModN.Bytes())
	pkx, pky := DefaultCurveType.Add(cGx, cGy, mx, my)

	if index == 0 {
		pk0 := &ecdsa.PublicKey{
			Curve: DefaultCurveType,
			X:     x,
			Y:     y,
		}
		return k, pk0, nil
	} else if index == 1 {
		pk0 := &ecdsa.PublicKey{
			Curve: DefaultCurveType,
			X:     pkx,
			Y:     pky,
		}
		return k, pk0, nil
	}
	return nil, nil, fmt.Errorf("invalid index, supposed to be smaller than %d", DefaultMsgLen)
}

// ComputeCs compute cipherMs
func ComputeCs(c *big.Int, pk0 *ecdsa.PublicKey, ms []*big.Int) ([]CipherM, error) {
	if len(ms) != DefaultMsgLen {
		return nil, fmt.Errorf("invalid messaage length, supposed to be %d", DefaultMsgLen)
	}
	// pk1 = cG-pk0
	cGx, cGy := DefaultCurveType.ScalarBaseMult(c.Bytes())
	nx, ny := DefaultCurveType.ScalarMult(pk0.X, pk0.Y, minusOneModN.Bytes())
	pk1x, pk1y := DefaultCurveType.Add(cGx, cGy, nx, ny)

	// random r0 and r1
	r0, err := rand.Int(rand.Reader, DefaultCurveType.Params().N)
	if err != nil {
		return nil, err
	}
	r1, err := rand.Int(rand.Reader, DefaultCurveType.Params().N)
	if err != nil {
		return nil, err
	}

	r0Gx, r0Gy := DefaultCurveType.ScalarBaseMult(r0.Bytes())
	r1Gx, r1Gy := DefaultCurveType.ScalarBaseMult(r1.Bytes())

	pk0r0x, pk0r0y := DefaultCurveType.ScalarMult(pk0.X, pk0.Y, r0.Bytes())
	pk1r1x, pk1r1y := DefaultCurveType.ScalarMult(pk1x, pk1y, r1.Bytes())

	hashPk0r0 := hashP(pk0r0x, pk0r0y)
	hashPk1r1 := hashP(pk1r1x, pk1r1y)

	encM0 := new(big.Int).Add(hashPk0r0, ms[0])
	encM1 := new(big.Int).Add(hashPk1r1, ms[1])

	c0 := CipherM{
		RG: &ecdsa.PublicKey{
			Curve: DefaultCurveType,
			X:     r0Gx,
			Y:     r0Gy,
		},
		EncM: encM0,
	}
	c1 := CipherM{
		RG: &ecdsa.PublicKey{
			Curve: DefaultCurveType,
			X:     r1Gx,
			Y:     r1Gy,
		},
		EncM: encM1,
	}

	return []CipherM{c0, c1}, nil
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
