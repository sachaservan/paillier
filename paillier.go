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
	V          int      // n choose t where t is the corruption threshold
	FPPrecBits int      // fixed point precision bits
}

type SecretKey struct {
	PublicKey
	Lambda, Lm, Mu *big.Int
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
	ret := fmt.Sprintf("g     :  %x", sk.G)
	ret += fmt.Sprintf("n     :  %x", sk.N)
	ret += fmt.Sprintf("lambda:  %x", sk.Lambda)
	ret += fmt.Sprintf("mu    :  %x", sk.Mu)
	return ret
}

// TODO: use this when using the modified scheme
// func (priv *SecretKey) Decrypt(ciphertext *Ciphertext) *big.Int {
// 	num := L(new(big.Int).Exp(ciphertext.C, priv.Lambda, priv.GetNSquare()), priv.N)
// 	den := L(new(big.Int).Exp(priv.G, priv.Lambda, priv.GetNSquare()), priv.N)
// 	msg := new(big.Int).Mod(new(big.Int).Div(num, den), priv.N)
// 	return msg
// }

func (priv *SecretKey) Decrypt(ciphertext *Ciphertext) *big.Int {
	tmp := new(big.Int).Exp(ciphertext.C, priv.Lambda, priv.GetNSquare())
	msg := new(big.Int).Mod(new(big.Int).Mul(L(tmp, priv.N), priv.Mu), priv.N)
	return msg
}

func (pk *PublicKey) Encrypt(pt *big.Int) *Ciphertext {
	r, err := GetRandomNumberInMultiplicativeGroup(pk.N, rand.Reader)
	if err != nil {
		panic(err)
	}

	nSquare := pk.GetNSquare()

	gm := new(big.Int).Exp(pk.G, pt, nSquare)
	gr := new(big.Int).Exp(pk.G, r, nSquare)
	gr = gr.Exp(gr, pk.N, nSquare)

	return &Ciphertext{new(big.Int).Mod(new(big.Int).Mul(gm, gr), nSquare)}
}

func L(u, n *big.Int) *big.Int {
	t := new(big.Int).Add(u, big.NewInt(-1))
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

func CreateSecretKey(p, q *big.Int) *SecretKey {
	n := new(big.Int).Mul(p, q)
	lambda := new(big.Int).Mul(minusOne(p), minusOne(q))
	g := new(big.Int).Add(n, big.NewInt(1))
	mu := new(big.Int).ModInverse(lambda, n)
	return &SecretKey{
		PublicKey: PublicKey{
			N: n,
			G: g,
		},
		Lambda: lambda,
		Mu:     mu,
	}
}
