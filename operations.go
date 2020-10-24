package paillier

import (
	"fmt"

	gmp "github.com/ncw/gmp"
)

// Add homomorphically adds encrypted values
func (pk *PublicKey) Add(cts ...*Ciphertext) *Ciphertext {
	accumulator := gmp.NewInt(1)
	level := cts[0].Level

	_, _, ns1 := pk.getModuliForLevel(level)

	for _, c := range cts {
		accumulator = new(gmp.Int).Mod(
			new(gmp.Int).Mul(accumulator, c.C),
			ns1,
		)
	}

	return &Ciphertext{
		C:     accumulator,
		Level: level,
	}
}

// Sub homomorphically subtracts encrypted values from the first value
func (pk *PublicKey) Sub(cts ...*Ciphertext) *Ciphertext {

	accumulator := cts[0].C
	level := cts[0].Level

	_, _, ns1 := pk.getModuliForLevel(level)

	for i, c := range cts {
		if i == 0 {
			continue
		}
		neg := new(gmp.Int).ModInverse(c.C, ns1)
		accumulator = new(gmp.Int).Mod(
			new(gmp.Int).Mul(accumulator, neg),
			ns1,
		)
	}

	return &Ciphertext{
		C:     accumulator,
		Level: level,
	}
}

// ConstMult multiplies an encrypted value by constant
func (pk *PublicKey) ConstMult(ct *Ciphertext, k *gmp.Int) *Ciphertext {

	_, _, ns1 := pk.getModuliForLevel(ct.Level)

	m := new(gmp.Int).Exp(ct.C, k, ns1)
	return &Ciphertext{m, ct.Level}
}

// Randomize randomizes an encryption
func (pk *PublicKey) Randomize(ct *Ciphertext) *Ciphertext {
	return pk.Add(ct, pk.Encrypt(ZeroBigInt))
}

// NestedRandomize homomorphically randomizes a nested encryption
// (only works with doubly encrypted values)
func (pk *PublicKey) NestedRandomize(ct *Ciphertext) *Ciphertext {
	if ct.Level != EncLevelThree {
		panic("can only homomorphically randomize doubly encrypted values")
	}

	rand := pk.Encrypt(ZeroBigInt)

	return pk.ConstMult(ct, rand.C)
}

// NestedAdd homomorphically adds an encrypted value to a doubly encrypted value
func (pk *PublicKey) NestedAdd(ct1 *Ciphertext, ct2 *Ciphertext) *Ciphertext {
	if ct1.Level != EncLevelThree || ct2.Level != EncLevelTwo {
		panic("can only homomorphically add an encrypted value to a doubly encrypted value")
	}

	return pk.ConstMult(ct1, ct2.C)
}

// NestedSub homomorphically subtracts  an encrypted value from a doubly encrypted value
func (pk *PublicKey) NestedSub(ct1 *Ciphertext, ct2 *Ciphertext) *Ciphertext {
	if ct1.Level != EncLevelThree || ct2.Level != EncLevelTwo {
		panic("can only homomorphically add an encrypted value to a doubly encrypted value")
	}

	_, _, ns1 := pk.getModuliForLevel(ct2.Level)

	neg := new(gmp.Int).ModInverse(ct2.C, ns1)

	return pk.ConstMult(ct1, neg)
}

func (sk *SecretKey) String() string {
	ret := fmt.Sprintf("g     :  %s\n", sk.G.String())
	ret += fmt.Sprintf("n     :  %s\n", sk.N.String())
	ret += fmt.Sprintf("lambda:  %s\n", sk.Lambda.String())
	ret += fmt.Sprintf("mu    :  %s\n", sk.Mu.String())
	return ret
}
