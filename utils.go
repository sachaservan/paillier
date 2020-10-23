package paillier

import (
	"crypto/rand"
	"io"
	"math/big"

	gmp "github.com/ncw/gmp"
)

var ZeroBigInt = gmp.NewInt(0)
var OneBigInt = gmp.NewInt(1)
var TwoBigInt = gmp.NewInt(2)
var FourBigInt = gmp.NewInt(4)

// Factorial returns n! = n*(n-1)*(n-2)...3*2*1
func Factorial(n int) *gmp.Int {
	ret := gmp.NewInt(1)
	for i := 1; i <= n; i++ {
		ret = new(gmp.Int).Mul(ret, gmp.NewInt(int64(i)))
	}
	return ret
}

// GetRandomNumberInMultiplicativeGroup returns a random element in the group of all the elements in Z/nZ that
func GetRandomNumberInMultiplicativeGroup(n *gmp.Int, random io.Reader) (*gmp.Int, error) {
	rBig, err := rand.Int(random, ToBigInt(n))
	if err != nil {
		return nil, err
	}

	r := ToGmpInt(rBig)

	zero := gmp.NewInt(0)
	one := gmp.NewInt(1)
	if zero.Cmp(r) == 0 || one.Cmp(new(gmp.Int).GCD(nil, nil, n, r)) != 0 {
		return GetRandomNumberInMultiplicativeGroup(n, random)
	}
	return r, nil

}

// GetRandomGeneratorOfTheQuadraticResidue return a random generator of RQn with high probability.
// Note: Only works if the group factorization consists of safe primes.
func GetRandomGeneratorOfTheQuadraticResidue(n *gmp.Int, rand io.Reader) (*gmp.Int, error) {
	r, err := GetRandomNumberInMultiplicativeGroup(n, rand)
	if err != nil {
		return nil, err
	}
	return new(gmp.Int).Mod(new(gmp.Int).Mul(r, r), n), nil
}

// ToGmpInt converts a big.Int to gmp.Int
func ToGmpInt(a *big.Int) *gmp.Int {
	return new(gmp.Int).SetBytes(a.Bytes())
}

// ToBigInt converts a gmp.Int to big.Int
func ToBigInt(a *gmp.Int) *big.Int {
	return new(big.Int).SetBytes(a.Bytes())
}
