package psi

import (
	"crypto/elliptic"
	"math/big"
)

var (
	DefaultCurveType = elliptic.P256()
)

type Point struct {
	X *big.Int
	Y *big.Int
}

// calOPRFRequest receiver calculates r*xG to hide secret
func calOPRFRequest(secrets []*big.Int, r *big.Int) []Point {
	var points []Point
	for i := 0; i < len(secrets); i++ {
		x, y := DefaultCurveType.ScalarBaseMult(secrets[i].Bytes())
		x, y = DefaultCurveType.ScalarMult(x, y, r.Bytes())
		point := Point{
			X: x,
			Y: y,
		}
		points = append(points, point)
	}
	return points
}

// calOPRFResponse sender calculates k*r*xG to hide k
func calOPRFResponse(points []Point, secretK *big.Int) []Point {
	var respPoints []Point
	for i := 0; i < len(points); i++ {
		x, y := DefaultCurveType.ScalarMult(points[i].X, points[i].Y, secretK.Bytes())
		point := Point{
			X: x,
			Y: y,
		}
		respPoints = append(respPoints, point)
	}
	return respPoints
}

// recoverPRF receiver recovers k*xG(PRF) using r inverse
func recoverPRF(points []Point, r *big.Int) []Point {
	rInverse := new(big.Int).ModInverse(r, DefaultCurveType.Params().N)
	var recoverPoints []Point
	for i := 0; i < len(points); i++ {
		x, y := DefaultCurveType.ScalarMult(points[i].X, points[i].Y, rInverse.Bytes())
		point := Point{
			X: x,
			Y: y,
		}
		recoverPoints = append(recoverPoints, point)
	}
	return recoverPoints
}

// intersect get intersection of two sets
func intersect(xps, yps []Point, ys []*big.Int) []*big.Int {
	var intersection []*big.Int
	for idx, yp := range yps {
		if exist(yp, xps) {
			intersection = append(intersection, ys[idx])
		}
	}
	return intersection
}

// exist determine if a point is in a set
func exist(p Point, points []Point) bool {
	for _, point := range points {
		if p.X.Cmp(point.X) == 0 {
			return true
		}
	}
	return false
}
