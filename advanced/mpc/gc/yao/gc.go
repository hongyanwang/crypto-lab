package gc

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"reflect"

	"github.com/hongyanwang/crypto-lab/symmetric/aes"
)

const (
	ENCLEN   = 32
	TAGLEN   = 4
	BLOCKLEN = 16
)

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

// GenerateRandMap generate truth -> enc map
func GenerateRandMap(truthGates []Gate) (*EncGateMap, error) {
	encGateMap := &EncGateMap{
		Xmap: make(map[uint8][]byte),
		Ymap: make(map[uint8][]byte),
		Wmap: make(map[uint8][]byte),
	}
	for i := 0; i < len(truthGates); i++ {
		x := truthGates[i].X
		if _, ok := encGateMap.Xmap[x]; !ok {
			encX := make([]byte, ENCLEN)
			if _, err := io.ReadFull(rand.Reader, encX); err != nil {
				return nil, err
			}
			encGateMap.Xmap[x] = encX
		}
		y := truthGates[i].Y
		if _, ok := encGateMap.Ymap[y]; !ok {
			encY := make([]byte, ENCLEN)
			if _, err := io.ReadFull(rand.Reader, encY); err != nil {
				return nil, err
			}
			encGateMap.Ymap[y] = encY
		}
		w := truthGates[i].W
		if _, ok := encGateMap.Wmap[w]; !ok {
			encW := make([]byte, ENCLEN-TAGLEN)
			if _, err := io.ReadFull(rand.Reader, encW); err != nil {
				return nil, err

			}
			// to make encW verifiable, add tag to encW
			tag := sha256.Sum256(encW)
			encWbytes := make([]byte, ENCLEN)
			copy(encWbytes, encW)
			copy(encWbytes[ENCLEN-TAGLEN:], tag[:TAGLEN])
			encGateMap.Wmap[w] = encWbytes
		}
	}

	return encGateMap, nil
}

// GenerateEncGates generate random enc gate using gate map
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

// EncOutputs encrypt output of each gate using inputs
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

// DecOutput decrypts encrypted outputs and get the valid result
func DecOutput(encX, encY []byte, encWs [][]byte) ([]byte, error) {
	for i := 0; i < len(encWs); i++ {
		cipher := encWs[i]

		encYW, err := aes.Decrypt(cipher, encX)
		if err != nil {
			continue
		}
		if len(encYW)%BLOCKLEN != 0 {
			// to avoid the panic(input not full blocks)
			continue
		}
		encW, err := aes.Decrypt(encYW, encY)
		if err == nil && verifyEncW(encW) {
			return encW, nil
		}
	}
	return nil, fmt.Errorf("did not find any valid encW")
}

// verifyEncW verify if encW is valid
func verifyEncW(encW []byte) bool {
	length := len(encW)

	msg := make([]byte, length-TAGLEN)
	end := make([]byte, TAGLEN)
	copy(msg, encW[:length-TAGLEN])
	copy(end, encW[length-TAGLEN:])

	tag := sha256.Sum256(msg)
	if reflect.DeepEqual(tag[:TAGLEN], end) {
		return true
	}
	return false
}
