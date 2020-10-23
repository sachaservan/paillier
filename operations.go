package paillier

import (
	"fmt"

	gmp "github.com/ncw/gmp"
)

// Add homomorphically adds encrypted values
func (pk *PublicKey) Add(cts ...*Ciphertext) *Ciphertext {
	accumulator := gmp.NewInt(1)

	for _, c := range cts {
		accumulator = new(gmp.Int).Mod(
			new(gmp.Int).Mul(accumulator, c.C),
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
		neg := new(gmp.Int).ModInverse(c.C, pk.GetN2())
		accumulator = new(gmp.Int).Mod(
			new(gmp.Int).Mul(accumulator, neg),
			pk.GetN2(),
		)
	}

	return &Ciphertext{
		C: accumulator,
	}
}

// ConstMult multiplies an encrypted value by constant
func (pk *PublicKey) ConstMult(ct *Ciphertext, k *gmp.Int) *Ciphertext {

	m := new(gmp.Int).Exp(ct.C, k, pk.GetN2())
	return &Ciphertext{new(gmp.Int).SetBytes(m.Bytes())}
}

// Randomize randomizes an encryption
func (pk *PublicKey) Randomize(ct *Ciphertext) *Ciphertext {
	return pk.Add(ct, pk.Encrypt(ZeroBigInt))
}

func (sk *SecretKey) String() string {
	ret := fmt.Sprintf("g     :  %s\n", sk.G.String())
	ret += fmt.Sprintf("n     :  %s\n", sk.N.String())
	ret += fmt.Sprintf("lambda:  %s\n", sk.Lambda.String())
	ret += fmt.Sprintf("mu    :  %s\n", sk.Mu.String())
	return ret
}
