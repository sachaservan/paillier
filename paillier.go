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
	// EncLevelTwo -- s=2
	EncLevelTwo EncryptionLevel = iota
	// EncLevelThree -- s=3
	EncLevelThree
)

// DefaultEncryptionLevel is set to s=2
const DefaultEncryptionLevel EncryptionLevel = EncLevelTwo

// PublicKey contains all the values necessary to encrypt and perform
// homomorphic operations over ciphertexts
type PublicKey struct {
	N        *gmp.Int //N=p*q
	G        *gmp.Int // usually G is set to N+1
	n2       *gmp.Int // cache value of N^2
	n3       *gmp.Int // cache value of N^3
	n2BigInt *big.Int // cache value of n^2 as big int type
}

// SecretKey contains the necessary values needed to decrypt a ciphertext
type SecretKey struct {
	PublicKey
	Lambda, Lm, Mu, m *gmp.Int
}

// Ciphertext contains the encryption of a value
type Ciphertext struct {
	C     *gmp.Int
	Level EncryptionLevel // generalized paillier encryption level
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

// GetN2AsBigInt returns N^2 where N is the Paillier modulus
func (pk *PublicKey) GetN2AsBigInt() *big.Int {
	if pk.n2BigInt != nil {
		return pk.n2BigInt
	}

	N := new(big.Int).SetBytes(pk.N.Bytes())
	pk.n2BigInt = new(big.Int).Mul(N, N)
	return pk.n2BigInt
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
func KeyGen(secparam int) (*SecretKey, *PublicKey) {

	if secparam%2 != 0 {
		panic("KeyGen: secparam must be divisible by 2")
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

		if p1.Cmp(q1) == 0 {
			continue
		}

		m = ToGmpInt(new(big.Int).Mul(p1, q1))

		p.SetBytes(p1.Bytes())
		q.SetBytes(q1.Bytes())
		break
	}

	n := new(gmp.Int).Mul(p, q)
	lambda := computePhi(p, q)

	pk := &PublicKey{
		N: n,
	}

	sk := &SecretKey{
		PublicKey: *pk,
		Lambda:    lambda,
		m:         m,
	}

	return sk, pk
}

// Decrypt a ciphertext to plaintext message.
func (sk *SecretKey) Decrypt(ciphertext *Ciphertext) *gmp.Int {

	s, ns, ns1 := sk.getModuliForLevel(ciphertext.Level)

	tmp := new(gmp.Int).Exp(ciphertext.C, sk.Lambda, ns1) // c^lambda mod N^s+1
	ml := sk.recoveryAlgorithm(tmp, s)                    // recoveryAlgorithm outputs m*lambda
	mu := new(gmp.Int).ModInverse(sk.Lambda, ns)          // lambda^-1

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

// EncryptWithR encrypts a plaintext into a cypher one with random `r` specified
// in the argument. The plain text must be smaller that N and bigger than or
// equal zero. `r` is the randomness used to encrypt the plaintext. `r` must be
// a random element from a multiplicative group of integers modulo N.
//
// If you don't need to use the specific `r`, you should use the `Encrypt`
// function instead.
//
// m - plaintext to encrypt
// r - randomness used for encryption
// E(m, r) = [(1 + N)^m r^N] mod N^2
//
// See [KL 08] construction 11.32, page 414.
func (pk *PublicKey) EncryptWithR(m *gmp.Int, r *gmp.Int) *Ciphertext {
	return pk.EncryptWithRAtLevel(m, r, DefaultEncryptionLevel)
}

// Encrypt a plaintext. The plain text must be smaller that
// N and bigger than or equal zero.
//
// m - plaintext to encrypt
// E(m, r) = [(1 + N) r^N] mod N^2
//
// See [KL 08] construction 11.32, page 414.
//
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
	g := new(gmp.Int).Add(pk.N, gmp.NewInt(1))
	gm := new(gmp.Int).Exp(g, m, ns1)
	rn := new(gmp.Int).Exp(r, ns, ns1)
	c := new(gmp.Int).Mod(new(gmp.Int).Mul(rn, gm), ns1)
	return &Ciphertext{c, level}
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
	if level == EncLevelThree {
		s = 2
		modPrevLevel = pk.GetN2()
		mod = pk.GetN3()
	}

	return s, modPrevLevel, mod
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
