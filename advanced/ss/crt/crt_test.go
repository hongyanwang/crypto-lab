package crt

import (
	"math/big"
	"testing"
)

var (
	secret, _ = new(big.Int).SetString("1234567890123456789012345678901234567890", 10)
	parties   = 8
	threshold = 5

	shares = make([]*Share, parties)
)

func TestCrt(t *testing.T) {
	var err error
	shares, err = GenerateShares(parties, threshold, secret)
	if err != nil {
		t.Error(err)
	}

	shareSelect := []*Share{shares[0], shares[2], shares[4], shares[6], shares[7]}
	s := RecoverSecret(shareSelect)
	if err != nil {
		t.Error(err)
	}

	if s.Cmp(secret) != 0 {
		t.Errorf("got: %v, supposed to be: %v", s, secret)
	}
}

func BenchmarkShare(b *testing.B) {
	for i := 0; i < b.N; i++ {
		shares, _ = GenerateShares(parties, threshold, secret)
	}
}

func BenchmarkRecover(b *testing.B) {
	for i := 0; i < b.N; i++ {
		RecoverSecret(shares[:threshold])
	}
}
