package ot

import (
	"crypto/rand"
	"math/big"

	"github.com/hongyanwang/crypto-lab/asymmetric/rsa"
)

var (
	// default secure bit
	defaultSecbit = 1024
)

// GenerateRandomSi owner generates {s_i} corresponding to {m_i}
func GenerateRandomSi(msgList [][]byte) (*rsa.PrivateKey, []*big.Int, error) {
	total := len(msgList)
	randS := make([]*big.Int, total)

	privkey, err := rsa.GenerateKey(defaultSecbit)
	if err != nil {
		return nil, nil, err
	}

	for i := 0; i < total; i++ {
		randS[i], err = rand.Int(rand.Reader, privkey.N)
		if err != nil {
			return nil, nil, err
		}
	}
	return privkey, randS, nil
}

// GenerateS receiver generates S = s_r + Enc(s)
func GenerateS(key *rsa.PublicKey, randS []*big.Int, target int) (*big.Int, *big.Int, error) {
	targetS := randS[target]
	s, err := rand.Int(rand.Reader, key.N)
	if err != nil {
		return nil, nil, err
	}

	encS, err := rsa.RSAEncrypt(s, key)
	if err != nil {
		return nil, nil, err
	}
	S := new(big.Int).Add(targetS, encS)

	return s, S, nil
}

// ComputePi owner computes {P_i} and transfer to receiver
func ComputePi(msgList [][]byte, randS []*big.Int, S *big.Int, privkey *rsa.PrivateKey) ([]*big.Int, error) {
	total := len(msgList)

	ks := make([]*big.Int, total)
	ps := make([]*big.Int, total)
	var err error
	for i := 0; i < total; i++ {
		// k[i] = Dec(S-si)
		si := new(big.Int).Sub(S, randS[i])
		ks[i], err = rsa.RSADecrypt(si, privkey)
		if err != nil {
			return nil, err
		}
		// p[i] = m[i] xor k[i]
		ps[i] = new(big.Int).Xor(new(big.Int).SetBytes(msgList[i]), ks[i])
	}
	return ps, nil
}

// RecoverM receiver computes desired message
func RecoverM(ps []*big.Int, s *big.Int, target int) []byte {
	targetP := ps[target]
	msg := new(big.Int).Xor(targetP, s)
	return msg.Bytes()
}
