package hd

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/sha512"
	"errors"
	"math/big"
)

var (
	P256Curve = elliptic.P256()

	zeroByte = []byte{0}

	zero           = new(big.Int).SetInt64(0)
	one            = new(big.Int).SetInt64(1)
	two            = new(big.Int).SetInt64(2)
	three          = new(big.Int).SetInt64(3)
	thirtyOne      = new(big.Int).SetInt64(31)
	normalIndexMax = new(big.Int).Exp(two, thirtyOne, nil)
)

// HDPrivateKey HD private key include a ecdsa private key and a chain code
type HDPrivateKey struct {
	Privkey   ecdsa.PrivateKey
	ChainCode *big.Int
}

// HDPublicKey HD public key include a ecdsa public key and a chain code
type HDPublicKey struct {
	PubKey    ecdsa.PublicKey
	ChainCode *big.Int
}

// PrivateToPrivate derive private key by private key using index
func PrivateToPrivate(parentPrivkey *HDPrivateKey, index *big.Int) *HDPrivateKey {
	// I = hmac(parCode, data)
	hmac := hmac.New(sha512.New, parentPrivkey.ChainCode.Bytes())
	var data []byte
	var I []byte

	// 1. check index >= 2^31, return hardened key
	if index.Cmp(normalIndexMax) == 1 {
		// data = 0x00 || D || index
		data = append(data, zeroByte...)
		data = append(data, parentPrivkey.Privkey.D.Bytes()...)
		data = append(data, index.Bytes()...)
		I = append(I, hmac.Sum(data)...)
	} else {
		// data = compressPK || index
		if new(big.Int).Mod(parentPrivkey.Privkey.Y, two).Cmp(one) == 0 {
			data = append(data, three.Bytes()...)
		} else {
			data = append(data, two.Bytes()...)
		}
		data = append(data, parentPrivkey.Privkey.X.Bytes()...)
		data = append(data, index.Bytes()...)
		I = append(I, hmac.Sum(data)...)
	}

	// 2. Il, Ir = I[:32], I[32:]
	Il, Ir := I[:32], I[32:]

	// 3. child key = Il + D (mod n)
	sum := new(big.Int).SetBytes(Il)
	sum = new(big.Int).Add(sum, parentPrivkey.Privkey.D)
	childD := new(big.Int).Mod(sum, parentPrivkey.Privkey.Params().N)
	x, y := P256Curve.ScalarBaseMult(childD.Bytes())

	// 4. child key chain code = Ir
	chaincode := new(big.Int).SetBytes(Ir)

	return &HDPrivateKey{
		Privkey: ecdsa.PrivateKey{
			PublicKey: ecdsa.PublicKey{
				Curve: parentPrivkey.Privkey.Curve,
				X:     x,
				Y:     y,
			},
			D: childD,
		},
		ChainCode: chaincode,
	}
}

// PublicToPublic derive public key by public key, cannot derive hardened key
func PublicToPublic(parentPubkey *HDPublicKey, index *big.Int) (*HDPublicKey, error) {
	// I = hmac(parCode, data)
	hmac := hmac.New(sha512.New, parentPubkey.ChainCode.Bytes())
	var data []byte

	// 1. check index < 2^31
	if index.Cmp(normalIndexMax) == 1 {
		return nil, errors.New("failed to derive hardened public key")
	}

	// data = compressPK || index
	if new(big.Int).Mod(parentPubkey.PubKey.Y, two).Cmp(one) == 0 {
		data = append(data, three.Bytes()...)
	} else {
		data = append(data, two.Bytes()...)
	}
	data = append(data, parentPubkey.PubKey.X.Bytes()...)
	data = append(data, index.Bytes()...)
	I := hmac.Sum(data)

	// 2. Il, Ir = I[:32], I[32:]
	Il, Ir := I[:32], I[32:]

	// 3. child key = Il*G + parentPubkey
	Ilx, Ily := P256Curve.ScalarBaseMult(Il)
	x, y := P256Curve.Add(Ilx, Ily, parentPubkey.PubKey.X, parentPubkey.PubKey.Y)

	// 4. child key chain code = Ir
	chaincode := new(big.Int).SetBytes(Ir)

	return &HDPublicKey{
		PubKey: ecdsa.PublicKey{
			Curve: parentPubkey.PubKey.Curve,
			X:     x,
			Y:     y,
		},
		ChainCode: chaincode,
	}, nil
}

// PrivateToPublic derive public key by private key
func PrivateToPublic(parentPrivkey *HDPrivateKey, index *big.Int) *HDPublicKey {
	childPrivkey := PrivateToPrivate(parentPrivkey, index)

	return &HDPublicKey{
		PubKey:    childPrivkey.Privkey.PublicKey,
		ChainCode: childPrivkey.ChainCode,
	}
}
