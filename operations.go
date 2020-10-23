package paillier

import (
	"fmt"
	"math/big"

	gmp "github.com/ncw/gmp"
)

// Add homomorphically adds encrypted values
func (pk *PublicKey) Add(cts ...*Ciphertext) *Ciphertext {
	accumulator := big.NewInt(1)

	for _, c := range cts {
		accumulator = new(big.Int).Mod(
			new(big.Int).Mul(accumulator, c.C),
			pk.GetN2(),
		)
	}

	return &Ciphertext{
		C: accumulator,
	}
}

// Sub homomorphically subtracts encrypted values from the first value
func (pk *PublicKey) Sub(cts ...*Ciphertext) *Ciphertext {

	accumulator := cts[0].C

	for i, c := range cts {
		if i == 0 {
			continue
		}
		neg := new(big.Int).ModInverse(c.C, pk.GetN2())
		accumulator = new(big.Int).Mod(
			new(big.Int).Mul(accumulator, neg),
			pk.GetN2(),
		)
	}

	return &Ciphertext{
		C: accumulator,
	}
}

// ConstMult multiplies an encrypted value by constant
func (pk *PublicKey) ConstMult(ct *Ciphertext, k *big.Int) *Ciphertext {

	gmpC := gmp.NewInt(0).SetBytes(ct.C.Bytes())
	gmpK := gmp.NewInt(0).SetBytes(k.Bytes())
	gmpN2 := gmp.NewInt(0).SetBytes(pk.GetN2().Bytes())

	m := new(gmp.Int).Exp(gmpC, gmpK, gmpN2)
	return &Ciphertext{new(big.Int).SetBytes(m.Bytes())}
}

func (sk *SecretKey) String() string {
	ret := fmt.Sprintf("g     :  %s\n", sk.G.String())
	ret += fmt.Sprintf("n     :  %s\n", sk.N.String())
	ret += fmt.Sprintf("lambda:  %s\n", sk.Lambda.String())
	ret += fmt.Sprintf("mu    :  %s\n", sk.Mu.String())
	return ret
}
