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
	E1         *big.Int         // initial random number
	Ss         []*big.Int       // random numbers
	LinkKey    *big.Int         // link key
}

// Sign
func Sign(partnerPubkeys []*rsa.PublicKey, privkey *rsa.PrivateKey, msg []byte) ([]byte, error) {
	if len(partnerPubkeys) < minimumPartners {
		return nil, fmt.Errorf("wrong partners number, supposed to be %d", minimumPartners)
	}

	// 1. generate a random index and insert signer's public key to index r
	max := new(big.Int).SetInt64(int64(len(partnerPubkeys) + 1))
	index, err := rand.Int(rand.Reader, max)
	if err != nil {
		return nil, fmt.Errorf("failed to generate random index, err: %v", err)
	}
	allPubkeys := make([]*rsa.PublicKey, len(partnerPubkeys)+1)
	copy(allPubkeys, partnerPubkeys[:int(index.Int64())])
	allPubkeys[int(index.Int64())] = &privkey.PublicKey
	copy(allPubkeys[int(index.Int64())+1:], partnerPubkeys[int(index.Int64()):])
	// get minimum N among all public keys
	minN := minN(allPubkeys)

	// 2. compute link key using private key
	linkKey := getLinkKey(privkey, minN)

	// 3. get E_{r+1} = hash(k*hash(P_r)+m) using random k
	k, err := rand.Int(rand.Reader, minN)
	if err != nil {
		return nil, fmt.Errorf("failed to generate random k, err: %v", err)
	}
	hashPr := sha256.Sum256(privkey.E.Bytes())
	kHashPr := new(big.Int).Mul(k, new(big.Int).SetBytes(hashPr[:]))
	kHashPr = kHashPr.Add(kHashPr, new(big.Int).SetBytes(msg))
	kHashPr = kHashPr.Mod(kHashPr, minN)
	er1Bytes := sha256.Sum256(kHashPr.Bytes())
	er1 := new(big.Int).SetBytes(er1Bytes[:])
	er1 = er1.Mod(er1, minN)

	ss := make([]*big.Int, len(allPubkeys))
	es := make([]*big.Int, len(allPubkeys))
	es[int(index.Int64()+1)%len(allPubkeys)] = er1

	// 4. get all Es and Ss
	// E_{i+1} = hash(s*hash(P_i)+E_i*linkKey+m)
	//for i:=index.Int64()+1; i<index.Int64(); i++{
	idx := index.Int64() + 1
	for {
		i := int(idx) % len(allPubkeys)
		if i == int(index.Int64()) {
			break
		}

		// get random number s
		s, err := rand.Int(rand.Reader, minN)
		if err != nil {
			return nil, fmt.Errorf("failed to generate random k, err: %v", err)
		}
		ss[i] = s

		hashPi := sha256.Sum256(allPubkeys[i].E.Bytes())
		sHashPi := new(big.Int).Mul(s, new(big.Int).SetBytes(hashPi[:]))
		eiLink := new(big.Int).Mul(es[i], linkKey)
		add := new(big.Int).Add(sHashPi, eiLink)
		add = add.Add(add, new(big.Int).SetBytes(msg))
		add = add.Mod(add, minN)
		e := sha256.Sum256(add.Bytes())
		es[(i+1)%len(allPubkeys)] = new(big.Int).SetBytes(e[:])

		idx++
	}

	// 5. find S_r=k-E_r*hash(s_r)
	hashsr := sha256.Sum256(privkey.D.Bytes())
	erHashsr := new(big.Int).Mul(es[index.Int64()], new(big.Int).SetBytes(hashsr[:]))
	Sr := new(big.Int).Sub(k, erHashsr)
	Sr = Sr.Mod(Sr, minN)
	ss[index.Int64()] = Sr

	// 6. construct signature
	signature := LinkRingSignature{
		PublicKeys: allPubkeys,
		E1:         es[0],
		Ss:         ss,
		LinkKey:    linkKey,
	}
	ret, err := json.Marshal(signature)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal signature, err: %v", err)
	}
	return ret, nil
}

// getLinkKey get link key based on private key, linkKey = hash(e)*hash(d) mod N
func getLinkKey(privkey *rsa.PrivateKey, minN *big.Int) *big.Int {
	hashE := sha256.Sum256(privkey.E.Bytes())
	hashD := sha256.Sum256(privkey.D.Bytes())
	linkKey := new(big.Int).Mul(new(big.Int).SetBytes(hashE[:]), new(big.Int).SetBytes(hashD[:]))
	linkKey = linkKey.Mod(linkKey, minN)
	return linkKey
}

// minN find minimum N among all public keys
func minN(keys []*rsa.PublicKey) *big.Int {
	min := keys[0].N
	for _, key := range keys {
		if key.N.Cmp(min) < 0 {
			min = key.N
		}
	}
	return min
}
