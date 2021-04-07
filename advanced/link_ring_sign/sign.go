package link_ring_sign

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/hongyanwang/crypto-lab/asymmetric/rsa"
)

var (
	// default secure bit size
	defaultSecbit = 1024

	// choose at least one member to hide identity
	minimumPartners = 1
)

// LinkRingSignature include 2n+2 members
type LinkRingSignature struct {
	PublicKeys []*rsa.PublicKey // all members' public keys
	V          *big.Int         // initial random number
	Xs         []*big.Int       // random numbers
	LinkKey    []byte           // link key
}

// Sign
func Sign(partnerPubkeys []*rsa.PublicKey, privkey *rsa.PrivateKey, msg []byte) ([]byte, error) {
	if len(partnerPubkeys) < minimumPartners {
		return nil, fmt.Errorf("wrong partners number, supposed to be %d", minimumPartners)
	}

	// 1. generate a random index and insert signer's public key to index
	max := new(big.Int).SetInt64(int64(len(partnerPubkeys) + 1))
	index, err := rand.Int(rand.Reader, max)
	if err != nil {
		return nil, fmt.Errorf("failed to generate random index, err: %v", err)
	}
	allPubkeys := make([]*rsa.PublicKey, len(partnerPubkeys)+1)
	copy(allPubkeys, partnerPubkeys[:int(index.Int64())])
	allPubkeys[int(index.Int64())] = &privkey.PublicKey
	copy(allPubkeys[int(index.Int64())+1:], partnerPubkeys[int(index.Int64()):])

	// 2. compute link key using private key
	linkKey := getLinkKey(privkey)

	// 3. key = hash(m|linkKey) is the encryption key
	key := sha256.Sum256(append(msg, linkKey...))

	// 3. get initial number v
	initialV, err := rand.Int(rand.Reader, minN(allPubkeys))
	if err != nil {
		return nil, fmt.Errorf("failed to generate initial v, err: %v", err)
	}

	xs := make([]*big.Int, len(allPubkeys))
	yr := big.NewInt(0)
	for {
		// 4. get random number list Xs
		for i := 0; i < len(xs); i++ {
			if i == int(index.Int64()) {
				continue
			}
			xs[i], err = rand.Int(rand.Reader, allPubkeys[i].N)
			if err != nil {
				return nil, fmt.Errorf("failed to generate random number list xs, err: %v", err)
			}
		}

		// 5. compute encryption loop to get y_r
		yr, err = getYr(allPubkeys, xs, int(index.Int64()), key[:], initialV)
		if err != nil {
			return nil, fmt.Errorf("failed to calculate yr, err: %v", err)
		}
		// yr has to be smaller than N
		if yr.Cmp(privkey.N) == -1 {
			break
		}
	}

	// 6. find x_r for signer
	xr, err := asymmetricDecrypt(yr.Bytes(), privkey)
	if err != nil {
		return nil, fmt.Errorf("failed to calculate xr, err: %v", err)
	}
	xs[index.Int64()] = new(big.Int).SetBytes(xr)

	// 7. construct signature
	signature := LinkRingSignature{
		PublicKeys: allPubkeys,
		V:          initialV,
		Xs:         xs,
		LinkKey:    linkKey,
	}
	ret, err := json.Marshal(signature)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal signature, err: %v", err)
	}
	return ret, nil
}

// getLinkKey get link key based on private key, linkKey = hash(d|e|N)
func getLinkKey(privkey *rsa.PrivateKey) []byte {
	msg := privkey.D.Bytes()
	msg = append(msg, privkey.E.Bytes()...)
	msg = append(msg, privkey.N.Bytes()...)
	linkKey := sha256.Sum256(msg)
	return linkKey[:]
}

// getYr solve Enc(y_n xor Enc(y_n-1 xor... Enc(y_1 xor v))) = v to find y_r
func getYr(pubkeys []*rsa.PublicKey, xs []*big.Int, index int, key []byte, v *big.Int) (*big.Int, error) {
	ynf, err := cky(pubkeys[:index], xs[:index], key, v)
	if err != nil {
		return nil, err
	}

	vs := v.Bytes()
	for i := len(pubkeys) - 1; i > index; i-- {
		yd := xor(vs, key)
		yi, err := asymmetricEncrypt(xs[i].Bytes(), pubkeys[i])
		if err != nil {
			return nil, err
		}
		vs = xor(yi, yd)
	}

	ydr := xor(vs, key)
	yr := xor(ydr, ynf)
	return new(big.Int).SetBytes(yr), nil
}

// cky Enc(y_n xor Enc(y_n-1 xor... Enc(y_1 xor v)))
// Enc(m) = m xor key
func cky(pubkeys []*rsa.PublicKey, xs []*big.Int, key []byte, v *big.Int) ([]byte, error) {
	if len(pubkeys) != len(xs) {
		return nil, fmt.Errorf("pubkeys length should be equal to xs length and greater than 1")
	}

	e := v.Bytes()
	for i := 0; i < len(pubkeys); i++ {
		yi, err := asymmetricEncrypt(xs[i].Bytes(), pubkeys[i])
		if err != nil {
			return nil, err
		}
		yvi := xor(yi, e)
		e = xor(yvi, key)
	}
	return e, nil
}

// asymmetricEncrypt rsa encryption
func asymmetricEncrypt(msg []byte, pubkey *rsa.PublicKey) ([]byte, error) {
	ct, err := rsa.RSAEncrypt(new(big.Int).SetBytes(msg), pubkey)
	return ct.Bytes(), err
}

// asymmetricDecrypt rsa decryption
func asymmetricDecrypt(ciphertext []byte, privkey *rsa.PrivateKey) ([]byte, error) {
	pt, err := rsa.RSADecrypt(new(big.Int).SetBytes(ciphertext), privkey)
	return pt.Bytes(), err
}

// xor
func xor(msg, key []byte) []byte {
	return new(big.Int).Xor(new(big.Int).SetBytes(msg), new(big.Int).SetBytes(key)).Bytes()
}

// minN find minimum N among all pulic keys
func minN(keys []*rsa.PublicKey) *big.Int {
	min := keys[0].N
	for _, key := range keys {
		if key.N.Cmp(min) < 0 {
			min = key.N
		}
	}
	return min
}
