package paillier

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

type Ciphertext struct {
	C *big.Int
}

type PublicKey struct {
	N          *big.Int //N=p*q
	G          *big.Int // usually G is set to N+1
	N2         *big.Int // the cache value of N^2
	K          int      // message space 2^K < N
	S          int      // security parameter for statistical secure MPC
	P          *big.Int // secret share prime
	FPPrecBits int      // fixed point precision bits
}

type SecretKey struct {
	PublicKey
	Alpha, Lambda, Lm, Mu *big.Int
}

func (pk *PublicKey) GetNSquare() *big.Int {
	if pk.N2 != nil {
		return pk.N2
	}
	pk.N2 = new(big.Int).Mul(pk.N, pk.N)
	return pk.N2
}

// EAdd add ct1 and ct2 homomorphically
func (pk *PublicKey) EAdd(ct1, ct2 *Ciphertext) *Ciphertext {
	m := new(big.Int).Mul(ct1.C, ct2.C)
	return &Ciphertext{new(big.Int).Mod(m, pk.GetNSquare())}
}

func (pk *PublicKey) ESub(ct1, ct2 *Ciphertext) *Ciphertext {
	neg := new(big.Int).ModInverse(ct2.C, pk.GetNSquare())
	m := new(big.Int).Mul(ct1.C, neg)
	return &Ciphertext{new(big.Int).Mod(m, pk.GetNSquare())}
}

func (pk *PublicKey) ECMult(ct *Ciphertext, k *big.Int) *Ciphertext {
	m := new(big.Int).Exp(ct.C, k, pk.GetNSquare())
	return &Ciphertext{m}
}

func (sk *SecretKey) String() string {
	ret := fmt.Sprintf("g     :  %s\n", sk.G.String())
	ret += fmt.Sprintf("n     :  %s\n", sk.N.String())
	ret += fmt.Sprintf("lambda:  %s\n", sk.Lambda.String())
	ret += fmt.Sprintf("alpha :  %s\n", sk.Alpha.String())
	ret += fmt.Sprintf("mu    :  %s\n", sk.Mu.String())
	return ret
}

func (priv *SecretKey) Decrypt(ciphertext *Ciphertext) *big.Int {

	num := L(new(big.Int).Exp(ciphertext.C, priv.Alpha, priv.GetNSquare()), priv.N)
	den := L(new(big.Int).Exp(priv.G, priv.Alpha, priv.GetNSquare()), priv.N)
	den = den.ModInverse(den, priv.N)
	msg := new(big.Int).Mod(new(big.Int).Mul(num, den), priv.N)
	return msg
}

func (pk *PublicKey) Encrypt(pt *big.Int) *Ciphertext {
	r, err := GetRandomNumberInMultiplicativeGroup(pk.N, rand.Reader)
	if err != nil {
		panic(err)
	}

	r = big.NewInt(1)

	nSquare := pk.GetNSquare()

	gm := new(big.Int).Exp(pk.G, pt, nSquare)
	gr := new(big.Int).Exp(pk.G, pk.N, nSquare)
	gr.Exp(gr, r, nSquare)

	return &Ciphertext{new(big.Int).Mod(new(big.Int).Mul(gm, gr), nSquare)}
}

func L(u, n *big.Int) *big.Int {
	t := new(big.Int).Sub(u, big.NewInt(1))
	return new(big.Int).Div(t, n)
}

func LCM(x, y *big.Int) *big.Int {
	return new(big.Int).Mul(new(big.Int).Div(x, new(big.Int).GCD(nil, nil, x, y)), y)
}

func minusOne(x *big.Int) *big.Int {
	return new(big.Int).Add(x, big.NewInt(-1))
}

func computeMu(g, lambda, n *big.Int) *big.Int {
	n2 := new(big.Int).Mul(n, n)
	u := new(big.Int).Exp(g, lambda, n2)
	return new(big.Int).ModInverse(L(u, n), n)
}

func computeLamda(p, q *big.Int) *big.Int {
	return LCM(minusOne(p), minusOne(q))
}

func CreateSecretKey(bits int) *SecretKey {

	p, alpha1, _ := GenerateSafePrimes(bits, rand.Reader)
	q, alpha2, _ := GenerateSafePrimes(bits, rand.Reader)

	for p.Cmp(q) == 0 {
		p, alpha1, _ = GenerateSafePrimes(bits, rand.Reader)
		q, alpha2, _ = GenerateSafePrimes(bits, rand.Reader)
	}

	p2 := new(big.Int).Mul(p, p)
	q2 := new(big.Int).Mul(q, q)

	g1 := new(big.Int).Exp(TWO, new(big.Int).Div(minusOne(p), alpha1), p)
	g2 := new(big.Int).Exp(TWO, new(big.Int).Div(minusOne(q), alpha2), q)

	z1 := new(big.Int).ModInverse(p2, q2)
	z2 := new(big.Int).ModInverse(q2, p2)

	g1 = new(big.Int).Mul(g1, z1)
	g1.Mul(g1, p2)
	g2 = new(big.Int).Mul(g2, z2)
	g2.Mul(g2, q2)

	n := new(big.Int).Mul(p, q)
	n2 := new(big.Int).Mul(n, n)

	g := new(big.Int).Add(g1, g2)
	g.Mod(g, n2)

	alpha := new(big.Int).Mul(alpha1, alpha2)
	lambda := new(big.Int).Mul(minusOne(p), minusOne(q))
	mu := new(big.Int).ModInverse(alpha, n)
	return &SecretKey{
		PublicKey: PublicKey{
			N: n,
			G: g,
		},
		Alpha:  alpha,
		Lambda: lambda,
		Mu:     mu,
	}
}
