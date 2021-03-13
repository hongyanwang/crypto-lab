package sm3

import "encoding/binary"

// message block size, 64 bytes
const BLOCKSIZE = 64

// initial vector
var IV = [8]uint32{0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600, 0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e}

// SM3 sm3 hash function
func SM3(msg []byte) []byte {
	msgPadding := padding(msg)
	n := len(msgPadding)
	v := IV
	for i := 0; i < n; i++ {
		v = CF(v, msgPadding[i])
	}

	ret := make([]byte, 32)
	for i := 0; i < 8; i++ {
		binary.BigEndian.PutUint32(ret[i*4:], v[i])
	}
	return ret
}

// CF compression function
func CF(v [8]uint32, b [16]uint32) [8]uint32 {
	msgExt := msgExtend(b)
	A, B, C, D, E, F, G, H := v[0], v[1], v[2], v[3], v[4], v[5], v[6], v[7]
	for i := 0; i < 64; i++ {
		ss1 := leftRotate(leftRotate(A, 12)+E+leftRotate(Ti(i), uint32(i)), 7)
		ss2 := ss1 ^ leftRotate(A, 12)
		tt1 := FFj(A, B, C, i) + D + ss2 + msgExt[i+68]
		tt2 := GGj(E, F, G, i) + H + ss1 + msgExt[i]
		D = C
		C = leftRotate(B, 9)
		B = A
		A = tt1
		H = G
		G = leftRotate(F, 19)
		F = E
		E = permutation0(tt2)
	}
	return [8]uint32{A ^ v[0], B ^ v[1], C ^ v[2], D ^ v[3], E ^ v[4], F ^ v[5], G ^ v[6], H ^ v[7]}
}

// msgExtend extend message block from [16]uint32 to [132]uint32
func msgExtend(block [16]uint32) [132]uint32 {
	var ret = [132]uint32{}

	for i := 0; i < 16; i++ {
		ret[i] = block[i]
	}
	for i := 16; i < 68; i++ {
		p1 := permutation1(ret[i-16] ^ ret[i-9] ^ (leftRotate(ret[i-3], 15)))
		ret[i] = p1 ^ (leftRotate(ret[i-13], 7)) ^ ret[i-6]
	}
	for i := 68; i < 132; i++ {
		ret[i] = ret[i-68] ^ ret[i-64]
	}

	return ret
}

// padding pad string to binary string, assume len(msg) < 2^64
func padding(msg []byte) [][16]uint32 {
	length := 8 * len(msg)

	// append 1
	msg = append(msg, 1<<7)

	// append k {00...0}, len(bin) + 1 + k = 448 mod 512
	for len(msg)%BLOCKSIZE != 56 {
		msg = append(msg, 0)
	}

	// append 64 len(m) s.t. len(m)+k+1+64 = 0 mod 512
	for i := 8; i > 0; i-- {
		msg = append(msg, byte(length>>(8*(i-1))&255))
	}

	// convert byte slice to uint32 slice
	var ret [][16]uint32
	n := len(msg) / BLOCKSIZE
	for i := 0; i < n; i++ {
		block := [16]uint32{}
		for j := 0; j < 16; j++ {
			begin := BLOCKSIZE*i + 4*j
			block[j] = binary.BigEndian.Uint32(msg[begin : begin+4])
		}
		ret = append(ret, block)
	}

	return ret
}

// Ti constant in compression function
func Ti(i int) uint32 {
	// 0<=j<=15
	if i < 16 {
		return 0x79cc4519
	}
	// 16<=j<=63
	return 0x7a879d8a
}

// FFj
func FFj(x, y, z uint32, j int) uint32 {
	if j < 16 {
		return x ^ y ^ z
	}
	return (x & y) | (x & z) | (y & z)
}

// GGj
func GGj(x, y, z uint32, j int) uint32 {
	if j < 16 {
		return x ^ y ^ z
	}
	return (x & y) | ((^x) & z)
}

// permutation0
func permutation0(x uint32) uint32 {
	return x ^ (leftRotate(x, 9)) ^ (leftRotate(x, 17))
}

// permutation1
func permutation1(x uint32) uint32 {
	return x ^ (leftRotate(x, 15)) ^ (leftRotate(x, 23))
}

// leftRotate cyclic left shift
func leftRotate(x uint32, i uint32) uint32 {
	return x<<(i%32) | x>>(32-i%32)
}
