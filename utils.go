package paillier

import (
	"crypto/rand"
	"io"
	"math/big"
)

var ZeroBigInt = big.NewInt(0)
var OneBigInt = big.NewInt(1)
var TwoBigInt = big.NewInt(2)
var FourBigInt = big.NewInt(4)

// Factorial returns n! = n*(n-1)*(n-2)...3*2*1
func Factorial(n int) *big.Int {
	ret := big.NewInt(1)
	for i := 1; i <= n; i++ {
		ret = new(big.Int).Mul(ret, big.NewInt(int64(i)))
	}
	return ret
}

// GetRandomNumberInMultiplicativeGroup returns a random element in the group of all the elements in Z/nZ that
func GetRandomNumberInMultiplicativeGroup(n *big.Int, random io.Reader) (*big.Int, error) {
	r, err := rand.Int(random, n)
	if err != nil {
		return nil, err
	}
	zero := big.NewInt(0)
	one := big.NewInt(1)
	if zero.Cmp(r) == 0 || one.Cmp(new(big.Int).GCD(nil, nil, n, r)) != 0 {
		return GetRandomNumberInMultiplicativeGroup(n, random)
	}
	return r, nil

}

// GetRandomGeneratorOfTheQuadraticResidue return a random generator of RQn with high probability.
// Note: Only works if the group factorization consists of safe primes.
func GetRandomGeneratorOfTheQuadraticResidue(n *big.Int, rand io.Reader) (*big.Int, error) {
	r, err := GetRandomNumberInMultiplicativeGroup(n, rand)
	if err != nil {
		return nil, err
	}
	return new(big.Int).Mod(new(big.Int).Mul(r, r), n), nil
}
