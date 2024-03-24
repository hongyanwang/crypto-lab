package iknp

import (
	"crypto/ecdsa"
	"crypto/sha1"
	"crypto/sha256"
	"fmt"
	"math"
	"math/big"
	"math/rand"
	"time"

	"github.com/hongyanwang/crypto-lab/symmetric/aes"
)

// Sender has {(x1_1, x1_2,... x1_2^l)... (xm_1, xm_2,... xm_2^l)} m sets of data
//   each set contains 2^l data.
// Receiver wants {r1, r2,... rm}, each ri is a bit vector {0, 1... 1,...0} with length l.
var (
	DefaultL   int64 = 16                // data number per set is 2^l
	DefaultM   int64 = 256               // data set number, also the row number of Receiver's matrix T,U
	DefaultK   int64 = 28                // column number of Receiver's matrix T,U, 3*secBit< K <4*secBit, secBit defined as 8
	DefaultMax       = big.NewInt(65536) // max value in the sample code, 2^16

	DefaultAESKey = sha1.Sum([]byte("default aes key")) // shared AES key to calculate error correcting code C, key length is 128 bytes
)

// CipherM encrypted message structure
type CipherM struct {
	RG   *ecdsa.PublicKey
	EncM *big.Int
}

type Matrix struct {
	Rows    [][]*big.Int // rows of a matrix, len(Rows) is number of rows, len(Rows[0]) is number of columns
	Columns [][]*big.Int // columns of a matrix, len(Columns) is number of columns, len(Columns[0]) is number of rows
}

// GenMatrixTU Receiver randomly generates matrix T and U with size m*k satisfies that rowT+rowU=<1,1...1>
func GenMatrixTU(m, k int64, rs [][]*big.Int) (Matrix, Matrix, error) {
	var ts, us [][]*big.Int
	for i := 0; int64(i) < m; i++ {
		rowT := randomVector(k, big.NewInt(2))
		ts = append(ts, rowT)

		cr, err := Cr(rs[i], k)
		if err != nil {
			return Matrix{}, Matrix{}, err
		}

		rowU, err := intsXor(rowT, cr)
		if err != nil {
			return Matrix{}, Matrix{}, err
		}
		us = append(us, rowU)
	}

	matrixT := Matrix{
		Rows:    ts,
		Columns: colsFromRows(ts),
	}
	matrixU := Matrix{
		Rows:    us,
		Columns: colsFromRows(us),
	}

	return matrixT, matrixU, nil
}

// GetMatrixQForTest simulate Sender receives matrix Q with secret s=<0,1,1,0...>
// colQ_i=colT_i if si=0, otherwise colQ_i=colU_i
// rowQ_j=rowT_j+[C(rj)·s]
func GetMatrixQForTest(s []*big.Int, matrixT, matrixU Matrix) (Matrix, error) {
	var cols [][]*big.Int
	for i := 0; i < len(s); i++ {
		if s[i].Cmp(big.NewInt(0)) == 0 {
			cols = append(cols, matrixT.Columns[i])
		} else {
			cols = append(cols, matrixU.Columns[i])
		}
	}
	return Matrix{
		Rows:    rowsFromCols(cols),
		Columns: cols,
	}, nil
}

// EncryptData Sender calculates ciphertext vector
// data is the m sets of data {(x1_1, x1_2,... x1_2^l)... (xm_1, xm_2,... xm_2^l)}
// returns m sets of ciphertext {(y1_1, y1_2,... y1_2^l)... (ym_1, ym_2,... ym_2^l)}
func EncryptData(data [][]*big.Int, matrixQ Matrix, s []*big.Int) ([][]*big.Int, error) {
	var res [][]*big.Int
	for i := 0; i < len(data); i++ {
		var ys []*big.Int
		for j := 0; j < len(data[0]); j++ {
			// H(qj Xor [C(rj) AND s])
			rj := intToBits(big.NewInt(int64(j)), int(DefaultL))
			cri, err := Cr(rj, int64(len(s)))
			if err != nil {
				return nil, fmt.Errorf("failed to compute cr by rj: %v", err)
			}
			cris, err := intsAnd(cri, s)
			if err != nil {
				return nil, fmt.Errorf("failed to compute AND of rj and s: %v", err)
			}
			qcris, err := intsXor(matrixQ.Rows[i], cris)
			if err != nil {
				return nil, fmt.Errorf("failed to compute XOR of qj and CriS: %v", err)
			}
			h := RO(qcris)
			// Y = X Xor H, value of X smaller than DefaultMax
			xbits := intToBits(data[i][j], int(DefaultL))
			ybits, err := intsXor(xbits, h)
			if err != nil {
				return nil, fmt.Errorf("failed to compute XOR of ybits and h: %v", err)
			}
			y := intFromBits(ybits)
			ys = append(ys, y)
		}

		res = append(res, ys)
	}
	return res, nil
}

// RetrieveData Receiver recovers desired data
// rs is the m sets of select vector {r1, r2,... rm}, each ri is a bit vector {0, 1... 1,...0} with length l.
// ciphers is ciphertext list {(y1_1, y1_2,... y1_2^l)... (ym_1, ym_2,... ym_2^l)}
// returns a sets of received data {x1, x2,... xm}
func RetrieveData(ciphers, rs [][]*big.Int, matrixT Matrix) ([]*big.Int, error) {
	var res []*big.Int
	for i := 0; i < len(rs); i++ {
		// H(ti)
		h := RO(matrixT.Rows[i])
		// X = Y Xor H
		wantIdx := intFromBits(rs[i])
		ybits := intToBits(ciphers[i][wantIdx.Int64()], int(DefaultL))
		xbits, err := intsXor(ybits, h)
		if err != nil {
			return nil, fmt.Errorf("failed to compute XOR of ybits and h: %v", err)
		}

		y := intFromBits(xbits)
		res = append(res, y)
	}
	return res, nil
}

// RO random oracle calculates H(x)
// output length is DefaultL
func RO(r []*big.Int) []*big.Int {
	num := intFromBits(r)
	hash := sha256.Sum256(num.Bytes())
	hashInt := new(big.Int).SetBytes(hash[:])
	return intToBits(hashInt, int(DefaultL))
}

// Cr calculates the value of C(r)
// C is defined as C(x) = AES(1||x)||AES(2||x)||AES(3||x)||AES(4||x)
// k is output length
func Cr(r []*big.Int, k int64) ([]*big.Int, error) {
	var rb []byte
	for i := 0; i < len(r); i++ {
		rb = append(rb, []byte(r[i].String())...)
	}

	var jointCipherHash []byte
	for i := 1; i < 5; i++ {
		msg := big.NewInt(int64(i)).Bytes()
		msg = append(msg, rb...)
		c, err := aes.Encrypt(msg, DefaultAESKey[:16])
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt[%v], err is: %v", msg, err)
		}

		cHash := sha1.Sum(c)
		jointCipherHash = append(jointCipherHash, cHash[:16]...)
	}

	byteLen := k / 8
	if int64(len(jointCipherHash)) < byteLen {
		return nil, fmt.Errorf("invalid paramters")
	}
	finalB := jointCipherHash[:byteLen]
	res := intToBits(new(big.Int).SetBytes(finalB), int(k))

	return res, nil
}

// retrieve columns from rows
func colsFromRows(rows [][]*big.Int) [][]*big.Int {
	colNum := len(rows[0])
	cols := make([][]*big.Int, colNum)
	for i := 0; i < len(rows); i++ {
		for j := 0; j < colNum; j++ {
			cols[j] = append(cols[j], rows[i][j])
		}
	}
	return cols
}

// retrieve rows from columns
func rowsFromCols(cols [][]*big.Int) [][]*big.Int {
	rowNum := len(cols[0])
	rows := make([][]*big.Int, rowNum)
	for i := 0; i < len(cols); i++ {
		for j := 0; j < rowNum; j++ {
			rows[j] = append(rows[j], cols[i][j])
		}
	}
	return rows
}

// convert a number to bit vector with length k
func intToBits(num *big.Int, k int) []*big.Int {
	res := make([]*big.Int, k)
	bitLen := num.BitLen()
	for i := 0; i < k; i++ {
		if i < k-bitLen {
			res[i] = big.NewInt(0)
		} else {
			b := new(big.Int).SetUint64(uint64(num.Bit(k - i - 1)))
			res[i] = b
		}
	}
	return res
}

// convert a bit vector to number
func intFromBits(num []*big.Int) *big.Int {
	res := big.NewInt(0)
	for i := 0; i < len(num); i++ {
		if num[i].Cmp(big.NewInt(1)) == 0 {
			exp := len(num) - i - 1
			e := new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(exp)), DefaultMax)
			res = res.Add(res, e)
		}
	}
	return res
}

// calculate AND of two big vectors
func intsAnd(x, y []*big.Int) ([]*big.Int, error) {
	if len(x) != len(y) {
		return nil, fmt.Errorf("two vector length not equal")
	}

	var res []*big.Int
	for i := 0; i < len(x); i++ {
		if x[i].Cmp(big.NewInt(1)) == 0 && y[i].Cmp(big.NewInt(1)) == 0 {
			res = append(res, big.NewInt(1))
		} else {
			res = append(res, big.NewInt(0))
		}
	}
	return res, nil
}

// calculate XOR of two big vectors
func intsXor(x, y []*big.Int) ([]*big.Int, error) {
	if len(x) != len(y) {
		return nil, fmt.Errorf("two vector length not equal")
	}

	var res []*big.Int
	for i := 0; i < len(x); i++ {
		if x[i].Cmp(y[i]) == 0 {
			res = append(res, big.NewInt(0))
		} else {
			res = append(res, big.NewInt(1))
		}
	}
	return res, nil
}

// randomVector randomly generate vector with length k, value smaller than max
func randomVector(k int64, max *big.Int) []*big.Int {
	var res []*big.Int
	for i := 0; int64(i) < k; i++ {
		t := time.Now().UnixNano()
		r := new(big.Int).Rand(rand.New(rand.NewSource(t)), max)
		res = append(res, r)

		time.Sleep(time.Nanosecond)
	}
	return res
}

// randomDataVectorForTest randomly generate m data set, each set contains k data, value smaller than max
//  only for test
func randomDataVectorForTest(m, k int64, max *big.Int) [][]*big.Int {
	var res [][]*big.Int
	for i := 0; int64(i) < m; i++ {
		fmt.Printf("generating data set: %d, size %d  ...\n", i, k)
		set := randomVector(k, max)
		res = append(res, set)
	}
	return res
}

// randomSelectVectorForTest randomly generates rs
//  only for test
func randomSelectVectorForTest(m, l int64) [][]*big.Int {
	var res [][]*big.Int
	for i := 0; int64(i) < m; i++ {
		fmt.Printf("generating select vector: %d, size %d  ...\n", i, l)
		set := randomVector(l, big.NewInt(2))
		res = append(res, set)
	}
	return res
}

// getWantedDataForTest retrieve wanted data using select vector and original dataset
//  only for test
func getWantedDataForTest(data, rs [][]*big.Int) ([]*big.Int, error) {
	if len(data) != len(rs) {
		return nil, fmt.Errorf("data and rs length not equal, %d not equal to %d", len(data), len(rs))
	}

	var res []*big.Int
	var wantedIdx []int64
	for i := 0; i < len(rs); i++ {
		// convert bit vector <1,0,...1,0> to idx number
		var idx int64
		lenRi := len(rs[0])
		for j := 0; j < lenRi; j++ {
			if rs[i][j].Cmp(big.NewInt(1)) == 0 {
				value := math.Exp2(float64(lenRi - j - 1))
				idx += int64(value)
			}
		}
		wantedIdx = append(wantedIdx, idx)
	}

	for i := 0; i < len(data); i++ {
		if int64(len(data[i])) <= wantedIdx[i] {
			return nil, fmt.Errorf("set[%d] data length smaller than ri, %d<%d", i, len(data[i]), wantedIdx[i])
		}
		res = append(res, data[i][wantedIdx[i]])
	}

	return res, nil
}
