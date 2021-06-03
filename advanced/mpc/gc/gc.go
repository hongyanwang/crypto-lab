package gc

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"reflect"

	"github.com/hongyanwang/crypto-lab/hash/sm3"
	"github.com/hongyanwang/crypto-lab/symmetric/aes"
)

const KEYLEN = 32

// one gate is (X,Y)->W
type Gate struct {
	X *big.Int
	Y *big.Int
	W *big.Int
}

// map truth input to enc
type EncGateMap struct {
	Xmap map[*big.Int]*big.Int // truth -> random int
	Ymap map[*big.Int]*big.Int
	Wmap map[*big.Int]*big.Int
}

// generate truth -> enc map
func GenerateRandMap(truthGates []Gate) (EncGateMap, error) {
	encGateMap := EncGateMap{
		Xmap: make(map[*big.Int]*big.Int),
		Ymap: make(map[*big.Int]*big.Int),
		Wmap: make(map[*big.Int]*big.Int),
	}
	for i := 0; i < len(truthGates); i++ {
		x := truthGates[i].X
		if _, ok := encGateMap.Xmap[x]; !ok {
			encX, err := rand.Int(rand.Reader, new(big.Int).Exp(big.NewInt(2), big.NewInt(256), nil))
			if err != nil {
				return encGateMap, err
			}
			encGateMap.Xmap[x] = encX
		}
		y := truthGates[i].Y
		if _, ok := encGateMap.Ymap[y]; !ok {
			encY, err := rand.Int(rand.Reader, new(big.Int).Exp(big.NewInt(2), big.NewInt(256), nil))
			if err != nil {
				return encGateMap, err
			}
			encGateMap.Ymap[y] = encY
		}
		w := truthGates[i].W
		if _, ok := encGateMap.Wmap[w]; !ok {
			encW, err := rand.Int(rand.Reader, new(big.Int).Exp(big.NewInt(2), big.NewInt(224), nil))
			if err != nil {
				return encGateMap, err
			}
			// to make encW verifiable, add tag to encW
			encWbytes := append(encW.Bytes(), sm3.SM3(encW.Bytes())[:4]...)
			encGateMap.Wmap[w] = new(big.Int).SetBytes(encWbytes)
		}
	}

	return encGateMap, nil
}

// generate random enc gate
func GenerateEncGates(truthGates []Gate, encGateMap EncGateMap) []Gate {
	encGates := make([]Gate, len(truthGates))
	for i := 0; i < len(truthGates); i++ {
		x := truthGates[i].X
		y := truthGates[i].Y
		w := truthGates[i].W
		encGate := Gate{
			X: encGateMap.Xmap[x],
			Y: encGateMap.Ymap[y],
			W: encGateMap.Wmap[w],
		}
		encGates = append(encGates, encGate)
	}
	return encGates
}

// encrypt output of each gate using inputs
func EncOutputs(encGates []Gate) ([]*big.Int, error) {
	var encWs []*big.Int
	for _, gate := range encGates {
		encYW, err := aes.Encrypt(gate.W.Bytes(), gate.Y.Bytes())
		if err != nil {
			return nil, err
		}
		encXYW, err := aes.Encrypt(encYW, gate.X.Bytes())
		if err != nil {
			return nil, err
		}
		encWs = append(encWs, new(big.Int).SetBytes(encXYW))
	}
	return encWs, nil
}

// bob decrypts encrypted outputs and get the valid one
func DecOutput(encX, encY *big.Int, encWs []*big.Int) (*big.Int, error) {
	for _, encW := range encWs {
		encYW, err := aes.Decrypt(encW.Bytes(), encX.Bytes())
		if err != nil {
			return nil, err
		}
		encW, err := aes.Decrypt(encYW, encY.Bytes())
		if err != nil {
			return nil, err
		}
		if verifyEncW(encW) {
			return new(big.Int).SetBytes(encW), nil
		}
	}
	return nil, fmt.Errorf("did not find any valid encW")
}

// verify if encW is valid
func verifyEncW(encW []byte) bool {
	len := len(encW)
	msg := encW[:len-4]
	tag := sm3.SM3(msg)
	if !reflect.DeepEqual(tag[:4], encW[len-4:]) {
		return false
	}
	return true
}
