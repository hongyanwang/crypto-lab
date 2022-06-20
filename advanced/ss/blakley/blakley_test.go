package blakley

import (
	"math/big"
	"testing"
)

var (
	secret    = big.NewInt(123)
	parties   = 8
	threshold = 5

	shares = make([][]*big.Int, parties)
)

func TestBlakley(t *testing.T) {
	var err error
	shares, err = GenerateShares(parties, threshold, secret)
	if err != nil {
		t.Error(err)
	}

	s, err := RecoverSecret(shares[:threshold])
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
