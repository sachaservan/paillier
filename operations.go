package paillier

import (
	"crypto/rand"
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
		C:         accumulator,
		Level:     level,
		EncMethod: MixedEncryption,
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
		C:         accumulator,
		Level:     level,
		EncMethod: MixedEncryption,
	}
}

// ConstMult multiplies an encrypted value by constant
func (pk *PublicKey) ConstMult(ct *Ciphertext, k *gmp.Int) *Ciphertext {

	_, _, ns1 := pk.getModuliForLevel(ct.Level)

	m := new(gmp.Int).Exp(ct.C, k, ns1)
	return &Ciphertext{m, ct.Level, ct.EncMethod}
}

// Randomize randomizes an encryption
func (pk *PublicKey) Randomize(ct *Ciphertext) *Ciphertext {
	return pk.Add(ct, pk.Encrypt(ZeroBigInt))
}

// ExtractRandonness returns the randomness used in the encryption
// See the following stack exchange post:
// https://crypto.stackexchange.com/questions/46736/how-to-prove-correct-decryption-in-paillier-cryptosystem
// for explanation
func (sk *SecretKey) ExtractRandonness(ct *Ciphertext) *gmp.Int {

	_, ns, ns1 := sk.getModuliForLevel(ct.Level)

	nsInv := new(gmp.Int).ModInverse(ns, sk.Lambda)

	v := sk.Decrypt(ct)
	gv := new(gmp.Int).Exp(sk.G, v, ns1)
	gvInv := gv.ModInverse(gv, ns1)

	z := gvInv.Mul(gvInv, ct.C) // make a ciphertext encrypting zero to isolate randomness
	z.Mod(z, ns1)

	res := new(gmp.Int).Exp(z, nsInv, sk.N)

	return res
}

// NestedRandomize homomorphically randomizes a nested encryption
// (only works with doubly encrypted values)
// returns randomized ciphertext and randomness used
func (pk *PublicKey) NestedRandomize(ct *Ciphertext) (*Ciphertext, *gmp.Int, *gmp.Int) {
	if ct.Level != EncLevelTwo {
		panic("can only homomorphically randomize doubly encrypted values")
	}

	n := pk.N
	n2 := pk.GetN2()
	n3 := pk.GetN3()

	a, _ := GetRandomNumberInMultiplicativeGroup(n, rand.Reader)
	b, _ := GetRandomNumberInMultiplicativeGroup(n, rand.Reader)

	an := new(gmp.Int).Exp(a, n, n2)
	bn2 := new(gmp.Int).Exp(b, n2, n3)

	r := new(gmp.Int).Set(ct.C)
	r.Exp(r, an, n3)
	r.Mul(r, bn2)
	r.Mod(r, n3)
	rct := &Ciphertext{C: r, Level: ct.Level, EncMethod: RegularEncryption}

	return rct, a, b
}

// NestedAdd homomorphically adds an encrypted value to a doubly encrypted value
func (pk *PublicKey) NestedAdd(ct1 *Ciphertext, ct2 *Ciphertext) *Ciphertext {
	if ct1.Level != EncLevelTwo || ct2.Level != EncLevelOne {
		panic("can only homomorphically add an encrypted value to a doubly encrypted value")
	}

	return pk.ConstMult(ct1, ct2.C)
}

// NestedSub homomorphically subtracts  an encrypted value from a doubly encrypted value
func (pk *PublicKey) NestedSub(ct1 *Ciphertext, ct2 *Ciphertext) *Ciphertext {
	if ct1.Level != EncLevelTwo || ct2.Level != EncLevelOne {
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
