package sm3

import (
	"testing"
)

func TestSM3(t *testing.T) {
	msg := []byte("test")
	hash := SM3(msg)
	t.Log(hash)
}

func BenchmarkSM3(b *testing.B) {
	msg := []byte("test")
	for i := 0; i < b.N; i++ {
		SM3(msg)
	}
}
