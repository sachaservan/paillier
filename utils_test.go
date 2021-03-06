package paillier

import (
	"crypto/rand"
	"math/big"
	"testing"

	gmp "github.com/ncw/gmp"
)

func b(i int) *gmp.Int {
	return gmp.NewInt(int64(i))
}

func n(i *gmp.Int) int {
	return int(i.Int64())
}

func areRelativelyPrime(a, b int) bool {
	if b == 0 {
		return a == 1
	}
	return areRelativelyPrime(b, a%b)
}

func TestConstants(t *testing.T) {
	if n(ZeroBigInt) != 0 {
		t.Fail()
	}

	if n(OneBigInt) != 1 {
		t.Fail()
	}

	if n(TwoBigInt) != 2 {
		t.Fail()
	}

	if n(FourBigInt) != 4 {
		t.Fail()
	}
}

func TestGetRandomNumberInMultiplicativeGroup(t *testing.T) {
	k := b(2 * 3 * 5 * 7)
	for i := 0; i < 100; i++ {
		m, err := GetRandomNumberInMultiplicativeGroup(k, rand.Reader)
		if err != nil {
			t.Error(err)
			return
		}
		if !areRelativelyPrime(n(k), n(m)) {
			t.Fail()
		}
	}
}

func TestFactorial(t *testing.T) {
	if delta := Factorial(6); 720 != delta.Int64() {
		t.Error("Delta is not 720 but", delta)
	}
}

// IsSafePrime checks whether `p` is a safe prime. A safe prime is a prime
// number of the form `2q + 1`, where `q` is also a prime.
func IsSafePrime(p, q *big.Int, expectedLength int, t *testing.T) {
	if l := p.BitLen(); l != expectedLength {
		t.Error("p does not have the good length. ", l)
	}
	if l := q.BitLen(); l != expectedLength-1 {
		t.Error("q does not have the good length. ", l)
	}
	if !p.ProbablyPrime(100) {
		t.Error("p is not a probable prime :(")
	}
	if !q.ProbablyPrime(100) {
		t.Error("q is not a probable prime :(")
	}
	if p.Int64() != 2*q.Int64()+1 {
		t.Error("p does not equals 2 * q + 1")
	}
}

func GetEntireRQn(n int) map[int]bool {
	ret := make(map[int]bool)
	for i := 1; i < n; i++ {
		if areRelativelyPrime(i, n) {
			ret[i] = true
		}
	}
	return ret
}

func TestGetRandomGeneratorOfTheQuadraticResidue(t *testing.T) {
	tooSmallPrime1, tooSmallPrime2 := b(347), b(359)
	m := new(gmp.Int).Mul(tooSmallPrime1, tooSmallPrime2)
	RQn := GetEntireRQn(n(m))
	for i := 0; i < 100; i++ {
		elm, err := GetRandomGeneratorOfTheQuadraticResidue(m, rand.Reader)
		if err != nil {
			t.Error(err)
			return
		}
		if _, ok := RQn[n(elm)]; !ok {
			t.Fail()
		}
	}

}
