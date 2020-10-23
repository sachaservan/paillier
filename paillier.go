package paillier

import (
	"crypto/rand"
	"math/big"

	gmp "github.com/ncw/gmp"
)

// PublicKey contains all the values necessary to encrypt and perform
// homomorphic operations over ciphertexts
type PublicKey struct {
	N        *gmp.Int //N=p*q
	G        *gmp.Int // usually G is set to N+1
	n2       *gmp.Int // cache value of N^2
	n2BigInt *big.Int // cache value of n^2 as big int type
}

// SecretKey contains the necessary values needed to decrypt a ciphertext
type SecretKey struct {
	PublicKey
	Lambda, Lm, Mu *gmp.Int
}

// Ciphertext contains the encryption of a value
// TODO: add s
type Ciphertext struct {
	C *gmp.Int
}

// GetN2 returns N^2 where N is the Paillier modulus
func (pk *PublicKey) GetN2() *gmp.Int {
	if pk.n2 != nil {
		return pk.n2
	}

	pk.n2 = new(gmp.Int).Mul(pk.N, pk.N)
	return pk.n2
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
	for {
		a, err := rand.Prime(rand.Reader, secparam/2)
		if err != nil {
			continue
		}
		b, err := rand.Prime(rand.Reader, secparam/2)
		if err != nil {
			continue
		}

		if a.Cmp(b) == 0 {
			continue
		}

		p.SetBytes(a.Bytes())
		q.SetBytes(b.Bytes())
		break
	}

	n := new(gmp.Int).Mul(p, q)
	lambda := computePhi(p, q)

	pk := &PublicKey{
		N: n,
	}

	return &SecretKey{
		PublicKey: *pk,
		Lambda:    lambda,
	}, pk
}

// Decrypt a ciphertext to plaintext message.
// D(c) = [ ((c^lambda) mod N^2) - 1) / N ] lambda^-1 mod N
// See [KL 08] construction 11.32, page 414.
func (sk *SecretKey) Decrypt(ciphertext *Ciphertext) *gmp.Int {

	tmp := new(gmp.Int).Exp(ciphertext.C, sk.Lambda, sk.GetN2())

	mu := new(gmp.Int).ModInverse(sk.Lambda, sk.N)
	m := new(gmp.Int).Mod(new(gmp.Int).Mul(l(tmp, sk.N), mu), sk.N)
	return m
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

	// g is _always_ equal n+1
	// Threshold encryption is safe only for g=n+1 choice.
	// See [DJN 10], section 5.1
	g := new(gmp.Int).Add(pk.N, gmp.NewInt(1))
	gm := new(gmp.Int).Exp(g, m, pk.GetN2())
	rn := new(gmp.Int).Exp(r, pk.N, pk.GetN2())
	c := new(gmp.Int).Mod(new(gmp.Int).Mul(rn, gm), pk.GetN2())
	return &Ciphertext{new(gmp.Int).SetBytes(c.Bytes())}
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

	var r *gmp.Int
	var err error
	for {
		r, err = GetRandomNumberInMultiplicativeGroup(pk.N, rand.Reader)
		if err == nil {
			break
		}
	}
	return pk.EncryptWithR(m, r)
}

// NullCiphertext returns an encryption of zero with no randomness
func (pk *PublicKey) NullCiphertext() *Ciphertext {
	return &Ciphertext{C: gmp.NewInt(0)}
}

func l(u, n *gmp.Int) *gmp.Int {
	t := new(gmp.Int).Sub(u, gmp.NewInt(1))
	return new(gmp.Int).Div(t, n)
}

func lcm(x, y *gmp.Int) *gmp.Int {
	return new(gmp.Int).Mul(new(gmp.Int).Div(x, new(gmp.Int).GCD(nil, nil, x, y)), y)
}

func computeMu(g, lambda, n *gmp.Int) *gmp.Int {
	n2 := new(gmp.Int).Mul(n, n)
	u := new(gmp.Int).Exp(g, lambda, n2)
	return new(gmp.Int).ModInverse(l(u, n), n)
}

func computePhi(p, q *gmp.Int) *gmp.Int {
	return new(gmp.Int).Mul(minusOne(p), minusOne(q))
}

// subtracts 1 from a big int
func minusOne(x *gmp.Int) *gmp.Int {
	return new(gmp.Int).Add(x, gmp.NewInt(-1))
}
