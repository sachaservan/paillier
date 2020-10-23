package paillier

import (
	"crypto/rand"
	"errors"
	"io"
	"math/big"
	"time"

	gmp "github.com/ncw/gmp"
)

// ThresholdKeyGenerator generates a threshold Paillier key with an algorithm based on [DJN 10],
// section 5.1, "Key generation".
//     [DJN 10]: Ivan Damgard, Mads Jurik, Jesper Buus Nielsen, (2010)
//               A Generalization of Paillier’s Public-Key System
//               with Applications to Electronic Voting
//               Aarhus University, Dept. of Computer Science, BRICS
type ThresholdKeyGenerator struct {
	PublicKeyBitLength             int
	TotalNumberOfDecryptionServers int
	Threshold                      int
	random                         io.Reader

	p *gmp.Int // p is prime of `PublicKeyBitLength/2` bits and `p = 2*p1 + 1`
	q *gmp.Int // q is prime of `PublicKeyBitLength/2` bits and `q = 2*q1 + 1`

	p1 *gmp.Int // p1 is prime of `PublicKeyBitLength/2 - 1` bits
	q1 *gmp.Int // q1 is prime of `PublicKeyBitLength/2 - 1` bits

	n       *gmp.Int // n=p*q and is of `PublicKeyBitLength` bits
	m       *gmp.Int // m = p1*q1
	nSquare *gmp.Int // nSquare = n*n
	nm      *gmp.Int // nm = n*m

	// As specified in the paper, d must satify d=1 mod n and d=0 mod m
	d *gmp.Int

	// A generator of QR in Z_{n^2}
	v *gmp.Int

	// The polynomial coefficients to hide a secret. See Shamir.
	polynomialCoefficients []*gmp.Int
}

// GenerateKeys returns as set of thrshold secret keys
func (tkg *ThresholdKeyGenerator) GenerateKeys() ([]*ThresholdSecretKey, error) {
	if err := tkg.initNumerialValues(); err != nil {
		return nil, err
	}
	if err := tkg.generateHidingPolynomial(); err != nil {
		return nil, err
	}
	return tkg.createPrivateKeys(), nil
}

// NewThresholdKeyGenerator is a preferable way to construct the ThresholdKeyGenerator.
// Due to the various properties that must be met for the threshold key to be
// considered valid, the minimum public key `N` bit length is 18 bits and the
// public key bit length should be an even number.
// The plaintext space for the key will be `Z_N`.
func NewThresholdKeyGenerator(
	publicKeyBitLength int,
	totalNumberOfDecryptionServers int,
	threshold int,
	random io.Reader,
) (*ThresholdKeyGenerator, error) {
	if publicKeyBitLength%2 == 1 {
		// For an odd n-bit number, we can't find two n/2-bit numbers with two
		// the most significant bits set on which multiplied gives an n-bit
		// number.
		return nil, errors.New("Public key bit length must be an even number")
	}
	if publicKeyBitLength < 18 {
		// We need to find two n/2-bit safe primes, P and Q which are not equal.
		// This is not possible for n<18.
		return nil, errors.New("Public key bit length must be at least 18 bits")
	}

	return &ThresholdKeyGenerator{
		PublicKeyBitLength:             publicKeyBitLength,
		TotalNumberOfDecryptionServers: totalNumberOfDecryptionServers,
		Threshold:                      threshold,
		random:                         random,
	}, nil
}

func (tkg *ThresholdKeyGenerator) generateSafePrimes() (*gmp.Int, *gmp.Int, error) {
	concurrencyLevel := 4
	timeout := 120 * time.Second
	safePrimeBitLength := tkg.PublicKeyBitLength / 2

	p, q, err := GenerateSafePrime(safePrimeBitLength, concurrencyLevel, timeout, tkg.random)
	if err != nil {
		return nil, nil, err
	}

	return ToGmpInt(p), ToGmpInt(q), nil
}

func (tkg *ThresholdKeyGenerator) initPandP1() error {
	var err error
	tkg.p, tkg.p1, err = tkg.generateSafePrimes()
	return err
}

func (tkg *ThresholdKeyGenerator) initQandQ1() error {
	var err error
	tkg.q, tkg.q1, err = tkg.generateSafePrimes()
	return err
}

func (tkg *ThresholdKeyGenerator) initShortcuts() {
	tkg.n = new(gmp.Int).Mul(tkg.p, tkg.q)
	tkg.m = new(gmp.Int).Mul(tkg.p1, tkg.q1)
	tkg.nSquare = new(gmp.Int).Mul(tkg.n, tkg.n)
	tkg.nm = new(gmp.Int).Mul(tkg.n, tkg.m)
}

func (tkg *ThresholdKeyGenerator) arePsAndQsGood() bool {
	if tkg.p.Cmp(tkg.q) == 0 {
		return false
	}
	if tkg.p.Cmp(tkg.q1) == 0 {
		return false
	}
	if tkg.p1.Cmp(tkg.q) == 0 {
		return false
	}
	return true
}

func (tkg *ThresholdKeyGenerator) initPsAndQs() error {
	if err := tkg.initPandP1(); err != nil {
		return err
	}
	if err := tkg.initQandQ1(); err != nil {
		return err
	}
	if !tkg.arePsAndQsGood() {
		return tkg.initPsAndQs()
	}
	return nil
}

// v generates a cyclic group of squares in Zn^2.
func (tkg *ThresholdKeyGenerator) computeV() error {
	var err error
	tkg.v, err = GetRandomGeneratorOfTheQuadraticResidue(tkg.nSquare, tkg.random)
	return err
}

// Choose d such that d=0 (mod m) and d=1 (mod n).
//
// From Chinese Remainder Theorem:
// x = a1 (mod n1)
// x = a2 (mod n2)
//
// N = n1*n2
// y1 = N/n1
// y2 = N/n2
// z1 = y1^-1 mod n1
// z2 = y2^-1 mod n2
// Solution is x = a1*y1*z1 + a2*y2*z2
//
// In our case:
// x = 0 (mod m)
// x = 1 (mod n)
//
// Since a1 = 0, it's enough to compute a2*y2*z2 to get x.
//
// a2 = 1
// y2 = mn/n = m
// z2 = m^-1 mod n
//
// x = a2*y2*z2 = 1 * m * [m^-1 mod n]
func (tkg *ThresholdKeyGenerator) initD() {
	mInverse := new(gmp.Int).ModInverse(tkg.m, tkg.n)
	tkg.d = new(gmp.Int).Mul(mInverse, tkg.m)
}

func (tkg *ThresholdKeyGenerator) initNumerialValues() error {
	if err := tkg.initPsAndQs(); err != nil {
		return err
	}
	tkg.initShortcuts()
	tkg.initD()
	return tkg.computeV()
}

// f(X) = a_0 X^0 + a_1 X^1 + ... + a_(w-1) X^(w-1)
//
// where:
// `w` - threshold
// `a_i` - random value from {0, ... nm - 1} for 0<i<w
// `a_0` is always equal `d`
func (tkg *ThresholdKeyGenerator) generateHidingPolynomial() error {
	tkg.polynomialCoefficients = make([]*gmp.Int, tkg.Threshold)
	tkg.polynomialCoefficients[0] = tkg.d
	for i := 1; i < tkg.Threshold; i++ {
		randInt, err := rand.Int(tkg.random, new(big.Int).SetBytes(tkg.nm.Bytes()))
		if err != nil {
			return err
		}
		tkg.polynomialCoefficients[i] = new(gmp.Int).SetBytes(randInt.Bytes())

	}
	return nil
}

// The secred share of the i'th authority is `f(i) mod nm`, where `f` is
// the polynomial we generated in `GenerateHidingPolynomial` function.
func (tkg *ThresholdKeyGenerator) computeShare(index int) *gmp.Int {
	share := gmp.NewInt(0)
	for i := 0; i < tkg.Threshold; i++ {
		a := tkg.polynomialCoefficients[i]
		// we index authorities from 1, that's why we do index+1 here
		b := new(gmp.Int).Exp(gmp.NewInt(int64(index+1)), gmp.NewInt(int64(i)), nil)
		tmp := new(gmp.Int).Mul(a, b)
		share = new(gmp.Int).Add(share, tmp)
	}
	return new(gmp.Int).Mod(share, tkg.nm)
}

func (tkg *ThresholdKeyGenerator) createShares() []*gmp.Int {
	shares := make([]*gmp.Int, tkg.TotalNumberOfDecryptionServers)
	for i := 0; i < tkg.TotalNumberOfDecryptionServers; i++ {
		shares[i] = tkg.computeShare(i)
	}
	return shares
}

func (tkg *ThresholdKeyGenerator) delta() *gmp.Int {
	return Factorial(tkg.TotalNumberOfDecryptionServers)
}

// Generates verification keys for actions of decryption servers.
//
// For each decryption server `i`, we generate
// v_i = v^(l! s_i) mod n^2
//
// where:
// `l` is the number of decryption servers
// `s_i` is a secret share for server `i`.
// Secret shares were previously generated in the `CrateShares` function.
func (tkg *ThresholdKeyGenerator) createVerificationKeys(shares []*gmp.Int) (viArray []*gmp.Int) {
	viArray = make([]*gmp.Int, len(shares))
	delta := tkg.delta()
	for i, share := range shares {
		tmp := new(gmp.Int).Mul(share, delta)
		viArray[i] = new(gmp.Int).Exp(tkg.v, tmp, tkg.nSquare)
	}
	return viArray
}

func (tkg *ThresholdKeyGenerator) createSecretKey(i int, share *gmp.Int, verificationKeys []*gmp.Int) *ThresholdSecretKey {
	ret := new(ThresholdSecretKey)
	ret.N = tkg.n
	ret.VerificationKey = tkg.v

	ret.TotalNumberOfDecryptionServers = tkg.TotalNumberOfDecryptionServers
	ret.Threshold = tkg.Threshold
	ret.Share = share
	ret.ID = i + 1
	ret.VerificationKeys = verificationKeys
	return ret
}

func (tkg *ThresholdKeyGenerator) createPrivateKeys() []*ThresholdSecretKey {
	shares := tkg.createShares()
	verificationKeys := tkg.createVerificationKeys(shares)
	ret := make([]*ThresholdSecretKey, tkg.TotalNumberOfDecryptionServers)
	for i := 0; i < tkg.TotalNumberOfDecryptionServers; i++ {
		ret[i] = tkg.createSecretKey(i, shares[i], verificationKeys)
	}
	return ret
}
