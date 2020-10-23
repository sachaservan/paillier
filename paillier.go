package paillier

import (
	"crypto/rand"
	"math/big"

	gmp "github.com/ncw/gmp"
)

// PublicKey contains all the values necessary to encrypt and perform
// homomorphic operations over ciphertexts
type PublicKey struct {
	N          *big.Int //N=p*q
	G          *big.Int // usually G is set to N+1
	N2         *big.Int // the cache value of N^2
	K          int      // message space 2^K < N
	S          int      // security parameter for statistical secure MPC
	P          *big.Int // secret share prime
	FPPrecBits int      // fixed point precision bits
}

// SecretKey contains the necessary values needed to decrypt a ciphertext
type SecretKey struct {
	PublicKey
	Lambda, Lm, Mu *big.Int
}

// Ciphertext contains the encryption of a value
// TODO: add s
type Ciphertext struct {
	C *big.Int
}

// GetN2 returns N^2 where N is the Paillier modulus
func (pk *PublicKey) GetN2() *big.Int {
	if pk.N2 != nil {
		return pk.N2
	}

	pk.N2 = new(big.Int).Mul(pk.N, pk.N)
	return pk.N2
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
	var p *big.Int
	var q *big.Int
	var err error
	for {
		p, err = rand.Prime(rand.Reader, secparam/2)
		if err != nil {
			continue
		}
		q, err = rand.Prime(rand.Reader, secparam/2)
		if err != nil {
			continue
		}

		if p.Cmp(q) == 0 {
			continue
		}
		break
	}

	n := new(big.Int).Mul(p, q)
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
func (sk *SecretKey) Decrypt(ciphertext *Ciphertext) *big.Int {

	gmpLambda := gmp.NewInt(0).SetBytes(sk.Lambda.Bytes())
	gmpC := gmp.NewInt(0).SetBytes(ciphertext.C.Bytes())
	gmpN2 := gmp.NewInt(0).SetBytes(sk.GetN2().Bytes())
	gmpTmp := new(gmp.Int).Exp(gmpC, gmpLambda, gmpN2)

	tmp := new(big.Int).SetBytes(gmpTmp.Bytes())
	mu := new(big.Int).ModInverse(sk.Lambda, sk.N)
	m := new(big.Int).Mod(new(big.Int).Mul(l(tmp, sk.N), mu), sk.N)
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
func (pk *PublicKey) EncryptWithR(m *big.Int, r *big.Int) *Ciphertext {

	nSquare := pk.GetN2()

	// g is _always_ equal n+1
	// Threshold encryption is safe only for g=n+1 choice.
	// See [DJN 10], section 5.1
	g := new(big.Int).Add(pk.N, big.NewInt(1))
	gmpG := gmp.NewInt(0).SetBytes(g.Bytes())
	gmpM := gmp.NewInt(0).SetBytes(m.Bytes())
	gmpN := gmp.NewInt(0).SetBytes(pk.N.Bytes())
	gmpN2 := gmp.NewInt(0).SetBytes(nSquare.Bytes())
	gmpR := gmp.NewInt(0).SetBytes(r.Bytes())
	gm := new(gmp.Int).Exp(gmpG, gmpM, gmpN2)
	rn := new(gmp.Int).Exp(gmpR, gmpN, gmpN2)
	c := new(gmp.Int).Mod(new(gmp.Int).Mul(rn, gm), gmpN2)
	return &Ciphertext{new(big.Int).SetBytes(c.Bytes())}
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
func (pk *PublicKey) Encrypt(m *big.Int) *Ciphertext {

	var r *big.Int
	var err error
	for {
		r, err = GetRandomNumberInMultiplicativeGroup(pk.N, rand.Reader)
		if err == nil {
			break
		}
	}
	return pk.EncryptWithR(m, r)
}

func l(u, n *big.Int) *big.Int {
	t := new(big.Int).Sub(u, big.NewInt(1))
	return new(big.Int).Div(t, n)
}

func lcm(x, y *big.Int) *big.Int {
	return new(big.Int).Mul(new(big.Int).Div(x, new(big.Int).GCD(nil, nil, x, y)), y)
}

func computeMu(g, lambda, n *big.Int) *big.Int {
	n2 := new(big.Int).Mul(n, n)
	u := new(big.Int).Exp(g, lambda, n2)
	return new(big.Int).ModInverse(l(u, n), n)
}

func computePhi(p, q *big.Int) *big.Int {
	return new(big.Int).Mul(minusOne(p), minusOne(q))
}

// subtracts 1 from a big int
func minusOne(x *big.Int) *big.Int {
	return new(big.Int).Add(x, big.NewInt(-1))
}
