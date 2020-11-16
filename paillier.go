package paillier

import (
	"bytes"
	"crypto/rand"
	"encoding/gob"
	"errors"
	"math/big"

	gmp "github.com/ncw/gmp"
)

// EncryptionLevel is the (modulus exponent) in the
// generalized paillier encryption scheme
type EncryptionLevel int

const (
	// EncLevelOne -- s=1
	EncLevelOne EncryptionLevel = iota

	// EncLevelTwo -- s=2
	EncLevelTwo
)

// EncryptionMethod specifies which encryption algorithm was used to
// encrypt the ciphertext
type EncryptionMethod int

const (
	// RegularEncryption is the same as in the original Paillier paper
	RegularEncryption EncryptionMethod = iota

	// AlternativeEncryption is the alternative encryption method of Damgard & Jurik
	AlternativeEncryption

	// MixedEncryption if multiple encryption methods were used in the ciphertext
	// e.g., following ops with different encryption methods
	MixedEncryption
)

// DefaultEncryptionLevel is set to s=2
const DefaultEncryptionLevel EncryptionLevel = EncLevelOne

// PublicKey contains all the values necessary to encrypt and perform
// homomorphic operations over ciphertexts
type PublicKey struct {
	N  *gmp.Int //N=p*q
	G  *gmp.Int // usually G is set to N+1
	n2 *gmp.Int // cache value of N^2
	n3 *gmp.Int // cache value of N^3
	h1 *gmp.Int
	h2 *gmp.Int
	K  *gmp.Int // power of two = 2^|bits N / 2|
}

// SecretKey contains the necessary values needed to decrypt a ciphertext
type SecretKey struct {
	PublicKey
	Lambda, Lm, Mu, m *gmp.Int
}

// Ciphertext contains the encryption of a value
type Ciphertext struct {
	C         *gmp.Int
	Level     EncryptionLevel // generalized paillier encryption level
	EncMethod EncryptionMethod
}

// GetN2 returns N^2 where N is the Paillier modulus
func (pk *PublicKey) GetN2() *gmp.Int {
	if pk.n2 != nil {
		return pk.n2
	}

	pk.n2 = new(gmp.Int).Mul(pk.N, pk.N)
	return pk.n2
}

// GetN3 returns N^3 where N is the Paillier modulus
func (pk *PublicKey) GetN3() *gmp.Int {
	if pk.n3 != nil {
		return pk.n3
	}

	pk.n3 = new(gmp.Int).Mul(pk.N, pk.N)
	pk.n3.Mul(pk.n3, pk.N)
	return pk.n3
}

// KeyGen generates a new keypair.
// Algorithm is based on approach described in [KL 08], construction 11.32,
// page 414 which is compatible with one described in [DJN 10], section 3.2
// except that instead of generating Lambda skate key component from LCM
// of p and q we use Euler's totient function as suggested in [KL 08].
//
//     [KL 08]:  Jonathan Katz, Yehuda Lindell, (2008)
//               Introduction to Modern Cryptography: Principles and Protocols,
//               Chapman & Hall/CRC
//
//     [DJN 10]: Ivan Damgard, Mads Jurik, Jesper Buus Nielsen, (2010)
//               A Generalization of Paillier’s Public-Key System
//               with Applications to Electronic Voting
//               Aarhus University, Dept. of Computer Science, BRICS
//
// If secure=true then will generate safe primes for the modulus
// this flag is useful to have for correctness testing since generating safe primes
// takes up to several minutes to generate
// https://crypto.stackexchange.com/questions/66076/how-to-efficiently-generate-a-random-safe-prime-of-given-length
//
func KeyGen(secparam int) (*SecretKey, *PublicKey) {

	if secparam%2 != 0 {
		panic("KeyGen: secparam must be divisible by 2")
	}

	if secparam < 64 {
		panic("KeyGen: secparam must be at least 64 bits")
	}

	// generate the prime factors
	p := new(gmp.Int)
	q := new(gmp.Int)
	m := new(gmp.Int)
	for {

		p1, err := rand.Prime(rand.Reader, secparam/2)
		if err != nil {
			continue
		}
		q1, err := rand.Prime(rand.Reader, secparam/2)
		if err != nil {
			continue
		}

		modTestP := new(big.Int).Mod(p1, big.NewInt(4))
		modTestQ := new(big.Int).Mod(q1, big.NewInt(4))

		// p and q must not be equal and must be congurent to 3 mod 4
		if p1.Cmp(q1) == 0 || modTestP.Cmp(big.NewInt(3)) != 0 || modTestQ.Cmp(big.NewInt(3)) != 0 {
			continue
		}

		m = ToGmpInt(new(big.Int).Mul(p1, q1))

		p.SetBytes(p1.Bytes())
		q.SetBytes(q1.Bytes())
		break
	}

	n := new(gmp.Int).Mul(p, q)
	n2 := new(gmp.Int).Mul(n, n)
	n3 := new(gmp.Int).Mul(n2, n)

	g := new(gmp.Int).Add(n, gmp.NewInt(1)) // generator = n + 1
	k := new(gmp.Int).Exp(TwoBigInt, gmp.NewInt(int64(secparam/2)), nil)
	lambda := computePhi(p, q)

	h, err := GetRandomGeneratorOfTheQuadraticResidue(n, rand.Reader)
	if err != nil {
		panic(err)
	}

	// see "Akternative encryption" section in
	// https://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.67.9647&rep=rep1&type=pdf
	// for explanation on how to generate a generator for the group of quadratic residues
	h1 := new(gmp.Int).Sub(n, h)
	h1.Exp(h1, n, n2)
	h2 := new(gmp.Int).Sub(n2, h)
	h2.Exp(h2, n2, n3)

	pk := &PublicKey{
		N:  n,
		G:  g,
		h1: h1,
		h2: h2,
		K:  k,
		n2: n2,
	}

	sk := &SecretKey{
		PublicKey: *pk,
		Lambda:    lambda,
		m:         m,
	}

	return sk, pk
}

// ProbablySafePrime reports whether x is probably safe prime, by calling big.Int.ProbablyPrime(n)
// on x as well as on (x-1)/2.
// If x is safe prime, ProbablySafePrime returns true.
// If x is chosen randomly and not safe prime, ProbablyPrime probably returns false.
func probablySafePrime(x *big.Int, n int) bool {
	y := new(big.Int).Rsh(x, 1)
	return y.ProbablyPrime(n)
}

// EncryptWithR encrypts a plaintext into a cypher one with random `r` specified
// in the argument. The plain text must be smaller that N and bigger than or
// equal zero. `r` is the randomness used to encrypt the plaintext. `r` must be
// a random element from a multiplicative group of integers modulo N.
func (pk *PublicKey) EncryptWithR(m *gmp.Int, r *gmp.Int) *Ciphertext {
	return pk.EncryptWithRAtLevel(m, r, DefaultEncryptionLevel)
}

// Encrypt a plaintext. The plain text must be smaller that
// N and bigger than or equal zero.
// Returns an error if an error has be returned by io.Reader.
func (pk *PublicKey) Encrypt(m *gmp.Int) *Ciphertext {
	return pk.EncryptAtLevel(m, DefaultEncryptionLevel)
}

// EncryptWithRAtLevel encrypts a plaintext as EncryptWithR but in the space N^s
func (pk *PublicKey) EncryptWithRAtLevel(m *gmp.Int, r *gmp.Int, level EncryptionLevel) *Ciphertext {

	_, ns, ns1 := pk.getModuliForLevel(level)

	// g is _always_ equal n+1
	// Threshold encryption is safe only for g=n+1 choice.
	// See [DJN 10], section 5.1
	gm := new(gmp.Int).Exp(pk.G, m, ns1)
	rn := new(gmp.Int).Exp(r, ns, ns1)

	c := new(gmp.Int).Mod(new(gmp.Int).Mul(gm, rn), ns1)
	return &Ciphertext{c, level, RegularEncryption}
}

// AltEncryptWithRAtLevel encrypts a plaintext as EncryptWithR but in the space N^s
func (pk *PublicKey) AltEncryptWithRAtLevel(m *gmp.Int, r *gmp.Int, level EncryptionLevel) *Ciphertext {

	_, _, ns1 := pk.getModuliForLevel(level)

	// generator for randomness
	h := pk.getGeneratorOfQuadraticResiduesForLevel(level)

	r.Mod(r, pk.K) // make sure randomness is in the correct range

	// g is _always_ equal n+1
	// Threshold encryption is safe only for g=n+1 choice.
	// See [DJN 10], section 5.1
	gm := new(gmp.Int).Exp(pk.G, m, ns1)
	hr := new(gmp.Int).Exp(h, r, ns1)

	c := new(gmp.Int).Mod(new(gmp.Int).Mul(gm, hr), ns1)
	return &Ciphertext{c, level, AlternativeEncryption}
}

// AltEncryptAtLevel encrypts a plaintext at the recusive level s
// using the alternative encryption method described in
// https://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.67.9647&rep=rep1&type=pdf
// Note: alternative encryption requires the public key N to be a composite of afe primes
func (pk *PublicKey) AltEncryptAtLevel(m *gmp.Int, level EncryptionLevel) *Ciphertext {

	var r *gmp.Int
	var err error
	for {
		r, err = GetRandomNumberInMultiplicativeGroup(pk.N, rand.Reader)
		if err == nil {
			break
		}
	}
	return pk.AltEncryptWithRAtLevel(m, r, level)
}

// EncryptAtLevel encrypts a plaintext at the recusive level s
func (pk *PublicKey) EncryptAtLevel(m *gmp.Int, level EncryptionLevel) *Ciphertext {

	var r *gmp.Int
	var err error
	for {
		r, err = GetRandomNumberInMultiplicativeGroup(pk.N, rand.Reader)
		if err == nil {
			break
		}
	}
	return pk.EncryptWithRAtLevel(m, r, level)
}

// EncryptZero returns a fresh encryption of 0
func (pk *PublicKey) EncryptZero() *Ciphertext {
	return pk.Encrypt(gmp.NewInt(0))
}

// EncryptOne returns a fresh encryption of 1
func (pk *PublicKey) EncryptOne() *Ciphertext {
	return pk.Encrypt(gmp.NewInt(1))
}

// EncryptZeroAtLevel returns a fresh encryption of 0 at the specified level
func (pk *PublicKey) EncryptZeroAtLevel(level EncryptionLevel) *Ciphertext {
	return pk.EncryptAtLevel(gmp.NewInt(0), level)
}

// EncryptOneAtLevel returns a fresh encryption of 1 at the specified Level
func (pk *PublicKey) EncryptOneAtLevel(level EncryptionLevel) *Ciphertext {
	return pk.EncryptAtLevel(gmp.NewInt(1), level)
}

// Decrypt a ciphertext to plaintext message.
func (sk *SecretKey) Decrypt(ct *Ciphertext) *gmp.Int {

	s, ns, ns1 := sk.getModuliForLevel(ct.Level)

	tmp := new(gmp.Int).Exp(ct.C, sk.Lambda, ns1) // c^lambda mod N^s+1
	ml := sk.recoveryAlgorithm(tmp, s)            // recoveryAlgorithm outputs m*lambda
	mu := new(gmp.Int).ModInverse(sk.Lambda, ns)  // lambda^-1

	m := new(gmp.Int).Mod(new(gmp.Int).Mul(ml, mu), ns)

	return m
}

// recovery algorithm used as a subroutine in the decryption alg of the generalized
// paillier scheme.
// See [J03] Proof of Theorem 2.1 for algorithm descryption
func (sk *SecretKey) recoveryAlgorithm(a *gmp.Int, s int) *gmp.Int {

	i := gmp.NewInt(0)

	for j := 1; j <= s; j++ {
		nj := new(gmp.Int).Exp(sk.N, gmp.NewInt(int64(j)), nil)    // n^j+1
		nj1 := new(gmp.Int).Exp(sk.N, gmp.NewInt(int64(j+1)), nil) // n^j+1

		amod := new(gmp.Int).Mod(a, nj1)

		t1 := L(amod, sk.N)
		t2 := new(gmp.Int).SetBytes(i.Bytes())

		for k := 2; k <= j; k++ {
			nk := new(gmp.Int).Exp(sk.N, gmp.NewInt(int64(k-1)), nil) // n^k-1
			i.Sub(i, OneBigInt)                                       // i = i-1

			t2.Mul(t2, i).Mod(t2, nj) // t2 = t2*i mod n^j

			// compute t2 = t1 - (t2*n^k-1) / k! mod n^j
			t2.Mul(t2, nk)
			kFac := Factorial(k)
			kFac.ModInverse(kFac, nj)
			t2.Mul(t2, kFac) // t2 = (t2*n^k-1) / k!
			t2.Sub(t1, t2)   // t2 = t1 - (t2*n^k-1) / k!
			t1.Mod(t2, nj)   // t1 =  t1 - (t2*n^k-1) / k! mod nj
		}

		i = t1
	}

	return i
}

// DecryptNestedCiphertext peels off one layer of decryption for a nested ciphertext
// e.g. returns [c] if given [[c]]
func (sk *SecretKey) DecryptNestedCiphertext(ct *Ciphertext) *Ciphertext {

	if ct.Level == EncLevelOne {
		panic("no nested ciphertexts to recover")
	}

	ctValue := sk.Decrypt(ct)
	if ct.Level == EncLevelTwo {
		return &Ciphertext{C: ctValue, Level: EncLevelOne, EncMethod: MixedEncryption}
	}

	// TODO: support decrypting arbitrary layers
	panic("not implemented")
}

// NewCiphertextFromBytes initializes a ciphertext from a byte encoding.
// Requires the public key to ensure field elements are correct (see PBC library)
func (pk *PublicKey) NewCiphertextFromBytes(data []byte) (*Ciphertext, error) {
	if len(data) == 0 {
		return nil, errors.New("no data provided")
	}

	ct := &Ciphertext{}

	reader := bytes.NewReader(data)
	dec := gob.NewDecoder(reader)
	if err := dec.Decode(ct); err != nil {
		return nil, err
	}

	return ct, nil
}

// Bytes returns the byte encoding of the ciphertext struct
func (ct *Ciphertext) Bytes() []byte {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	if err := enc.Encode(ct); err != nil {
		return nil
	}

	return buf.Bytes()
}

func (pk *PublicKey) getModuliForLevel(level EncryptionLevel) (int, *gmp.Int, *gmp.Int) {
	s := 1
	modPrevLevel := pk.N
	mod := pk.GetN2()
	if level == EncLevelTwo {
		s = 2
		modPrevLevel = pk.GetN2()
		mod = pk.GetN3()
	}

	return s, modPrevLevel, mod
}

func (pk *PublicKey) getGeneratorOfQuadraticResiduesForLevel(level EncryptionLevel) *gmp.Int {

	if level == EncLevelOne {
		return pk.h1
	}

	return pk.h2
}

// L is the function is paillier defined as (u-1)/n
func L(u, n *gmp.Int) *gmp.Int {
	t := new(gmp.Int).Sub(u, OneBigInt)
	return new(gmp.Int).Div(t, n)
}

func lcm(x, y *gmp.Int) *gmp.Int {
	return new(gmp.Int).Mul(new(gmp.Int).Div(x, new(gmp.Int).GCD(nil, nil, x, y)), y)
}

func computeMu(g, lambda, n *gmp.Int) *gmp.Int {
	n2 := new(gmp.Int).Mul(n, n)
	u := new(gmp.Int).Exp(g, lambda, n2)
	return new(gmp.Int).ModInverse(L(u, n), n)
}

func computePhi(p, q *gmp.Int) *gmp.Int {
	return new(gmp.Int).Mul(minusOne(p), minusOne(q))
}

// subtracts 1 from a big int
func minusOne(x *gmp.Int) *gmp.Int {
	return new(gmp.Int).Add(x, gmp.NewInt(-1))
}
