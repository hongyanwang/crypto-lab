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
	X uint8
	Y uint8
	W uint8
}

type EncGate struct {
	EncX []byte
	EncY []byte
	EncW []byte
}

// map truth input to enc
type EncGateMap struct {
	Xmap map[uint8][]byte // truth -> random big int
	Ymap map[uint8][]byte
	Wmap map[uint8][]byte
}

// generate truth -> enc map
func GenerateRandMap(truthGates []Gate) (*EncGateMap, error) {
	encGateMap := &EncGateMap{
		Xmap: make(map[uint8][]byte),
		Ymap: make(map[uint8][]byte),
		Wmap: make(map[uint8][]byte),
	}
	for i := 0; i < len(truthGates); i++ {
		x := truthGates[i].X
		if _, ok := encGateMap.Xmap[x]; !ok {
			encX, err := rand.Int(rand.Reader, new(big.Int).Exp(big.NewInt(2), big.NewInt(256), nil))
			if err != nil {
				return encGateMap, err
			}
			encGateMap.Xmap[x] = sm3.SM3(encX.Bytes())
		}
		y := truthGates[i].Y
		if _, ok := encGateMap.Ymap[y]; !ok {
			encY, err := rand.Int(rand.Reader, new(big.Int).Exp(big.NewInt(2), big.NewInt(256), nil))
			if err != nil {
				return encGateMap, err
			}
			encGateMap.Ymap[y] = sm3.SM3(encY.Bytes())
		}
		w := truthGates[i].W
		if _, ok := encGateMap.Wmap[w]; !ok {
			encW, err := rand.Int(rand.Reader, new(big.Int).Exp(big.NewInt(2), big.NewInt(256), nil))
			if err != nil {
				return encGateMap, err
			}
			// to make encW verifiable, add tag to encW
			hashW := sm3.SM3(encW.Bytes())[:28]
			encWbytes := append(hashW, sm3.SM3(hashW)[:4]...)
			encGateMap.Wmap[w] = encWbytes
		}
	}

	return encGateMap, nil
}

// generate random enc gate
func GenerateEncGates(truthGates []Gate, encGateMap *EncGateMap) []EncGate {
	var encGates []EncGate
	for _, gate := range truthGates {
		x := gate.X
		y := gate.Y
		w := gate.W
		encGate := EncGate{
			EncX: encGateMap.Xmap[x],
			EncY: encGateMap.Ymap[y],
			EncW: encGateMap.Wmap[w],
		}
		encGates = append(encGates, encGate)
	}
	return encGates
}

// encrypt output of each gate using inputs
func EncOutputs(encGates []EncGate) ([][]byte, error) {
	var encWs [][]byte
	for _, gate := range encGates {
		encYW, err := aes.Encrypt(gate.EncW, gate.EncY)
		if err != nil {
			return nil, err
		}
		encXYW, err := aes.Encrypt(encYW, gate.EncX)
		if err != nil {
			return nil, err
		}
		encWs = append(encWs, encXYW)
	}
	return encWs, nil
}

// bob decrypts encrypted outputs and get the valid one
func DecOutput(encX, encY []byte, encWs [][]byte) ([]byte, error) {
	for i := 0; i < len(encWs); i++ {
		cipher := encWs[i]

		encYW, err := aes.Decrypt(cipher, encX)
		if err != nil {
			return nil, err
		}

		encW, err := aes.Decrypt(encYW, encY)
		if err != nil && verifyEncW(encW) {
			return encW, nil
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
