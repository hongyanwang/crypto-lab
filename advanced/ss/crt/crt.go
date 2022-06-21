package crt

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"sort"

	"github.com/hongyanwang/crypto-lab/common/crt"
)

const (
	MinThreshold = 3
	secLen       = 32
)

// Share share distributed to each party
//  secret = Ri mod Mi
type Share struct {
	Modulus   *big.Int
	Remainder *big.Int
}

// GenerateShares generate N shares given number of participants and thresholds
//  each share contains a prime modulus and a remainder
func GenerateShares(partyNum, threshold int, secret *big.Int) ([]*Share, error) {
	if threshold < MinThreshold {
		return nil, fmt.Errorf("threshold is too small, at least: %d", MinThreshold)
	}

	primes := genModulus(secret, partyNum, threshold)
	shares := make([]*Share, 0, len(primes))
	for i := 0; i < len(primes); i++ {
		r := new(big.Int).Mod(secret, primes[i])
		share := &Share{
			Modulus:   primes[i],
			Remainder: r,
		}
		shares = append(shares, share)
	}
	return shares, nil
}

// RecoverSecret recover secret value using CRT
func RecoverSecret(shares []*Share) *big.Int {
	ms := make([]*big.Int, 0, len(shares))
	as := make([]*big.Int, 0, len(shares))
	for i := 0; i < len(shares); i++ {
		ms = append(ms, shares[i].Modulus)
		as = append(as, shares[i].Remainder)
	}

	return crt.Recover(ms, as)
}

// genModulus generate N coprime integers that satisfy
//  the secret is fewer than multiple of any t primes, and greater than multiple of any t-1 primes
func genModulus(secret *big.Int, partyNum, threshold int) []*big.Int {
	primes := make([]*big.Int, 0, partyNum)
	found := make(map[*big.Int]bool)
	for {
		if len(primes) == partyNum && checkModules(primes, secret, threshold) {
			break
		}

		p, _ := rand.Prime(rand.Reader, secLen)
		if found[p] {
			continue
		} else {
			found[p] = true
		}
		if len(primes) == partyNum {
			i, _ := rand.Int(rand.Reader, big.NewInt(int64(partyNum)))
			primes[i.Int64()] = p
			delete(found, primes[i.Int64()])
		} else {
			primes = append(primes, p)
		}
	}
	return primes
}

func checkModules(primes []*big.Int, secret *big.Int, threshold int) bool {
	sort.Sort(Primes(primes))
	left := big.NewInt(1)
	right := big.NewInt(1)
	for i := 0; i < threshold; i++ {
		left = left.Mul(left, primes[i])
	}
	for i := len(primes) - threshold + 1; i < len(primes); i++ {
		right = right.Mul(right, primes[i])
	}

	return secret.Cmp(left) < 0 && secret.Cmp(right) > 0
}

type Primes []*big.Int

func (p Primes) Less(i, j int) bool {
	return p[i].Cmp(p[j]) < 0
}
func (p Primes) Len() int {
	return len(p)
}
func (p Primes) Swap(i, j int) {
	p[i], p[j] = p[j], p[i]
}
