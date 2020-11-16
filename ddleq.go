package paillier

import (
	"crypto/rand"

	gmp "github.com/ncw/gmp"
)

// DDLEQProofInstance provides a proof that two ciphertexts
// are "nested re-encryptions" of one another
type DDLEQProofInstance struct {
	X, Y, Alpha, E, F *gmp.Int
}

// DDLEQProof constains a series of DDLEQProofInstance
// each providing soundness 1/2
type DDLEQProof struct {
	Instances []*DDLEQProofInstance
}

// ProveDDLEQ proves the following relation between ciphertexts
// ct2 = (ct1^a) * b  &  Dec(Dec(ct1)) == Dec(Dec(ct2))
// that is, ct2 is a "double re-encryption" of ct1
// for this to protocol to work, ct2 must be generated using NestedRandomize function.
// The resulting proof can be verified (non-interactively in the ROM) using VerifyDDLEQProof
// Soundness of the proof is 1 - 2^-secpar
func (sk *SecretKey) ProveDDLEQ(secpar int, ct1, ct2 *Ciphertext, a, b *gmp.Int) (*DDLEQProof, error) {

	p := &DDLEQProof{Instances: make([]*DDLEQProofInstance, secpar)}

	var err error
	for i := 0; i < secpar; i++ {
		p.Instances[i], err = sk.proveDDLEQInstance(ct1, ct2, a, b)
		if err != nil {
			return nil, err
		}
	}

	return p, nil
}

// VerifyDDLEQProof checks if the provided proof is valid for the ciphertexts
// the verification is done non-interactively and has soundness 1/2
func (pk *PublicKey) VerifyDDLEQProof(ct1 *Ciphertext, ct2 *Ciphertext, proof *DDLEQProof) bool {

	for i := 0; i < len(proof.Instances); i++ {
		if !pk.verifyDDLEQProofInstance(ct1, ct2, proof.Instances[i]) {
			return false
		}
	}

	return true
}

func (sk *SecretKey) proveDDLEQInstance(ct1, ct2 *Ciphertext, a, b *gmp.Int) (*DDLEQProofInstance, error) {

	// powers of n needed in the protocol
	n := sk.N
	n2 := sk.GetN2()
	n3 := sk.GetN3()

	sanityCheck := new(gmp.Int).Set(ct1.C)
	sanityCheck.Exp(sanityCheck, new(gmp.Int).Exp(a, n, n2), n3)
	sanityCheck.Mul(sanityCheck, new(gmp.Int).Exp(b, n2, n3))
	sanityCheck.Mod(sanityCheck, n3)

	if sanityCheck.Cmp(ct2.C) != 0 {
		panic("cannot prove re-encryption because inputs are wrong")
	}

	x, err := GetRandomNumberInMultiplicativeGroup(n, rand.Reader)
	if err != nil {
		return nil, err
	}

	y, err := GetRandomNumberInMultiplicativeGroup(n, rand.Reader)
	if err != nil {
		return nil, err
	}

	xn := new(gmp.Int).Exp(x, n, n2)
	yn2 := new(gmp.Int).Exp(y, n2, n3)

	// alpha = c1^{x^n} * y^{n^2}
	alpha := new(gmp.Int).Exp(ct1.C, xn, n3)
	alpha.Mul(alpha, yn2)
	alpha.Mod(alpha, n3)

	// Fiat-Shamir heuristic to get a random challenge bit
	// hashdata = c1 || c2 || r2 || s2 || alpha
	chalBit := RandomOracleBit(ct1.C, ct2.C, x, y, alpha)

	// e = x * (chalBit * a)^-1 mod phi(n)
	e := new(gmp.Int).Set(x)
	if chalBit {
		ainv := new(gmp.Int).ModInverse(a, n2)
		e.Mul(e, ainv)
		e.Mod(e, n2)
	}

	f := new(gmp.Int).Set(y)
	if chalBit {
		s := sk.ExtractRandonness(ct1)
		an := new(gmp.Int).Exp(a, n, n2)
		en := new(gmp.Int).Exp(e, n, n2)

		c := new(gmp.Int).Exp(s, an, n3)
		c.Mul(c, b)
		c.Exp(c, en, n3)
		c.ModInverse(c, n3)

		c.Mul(c, new(gmp.Int).Exp(s, xn, n3))
		f.Mul(f, c)
		f.Mod(f, n3)
	}

	proof := &DDLEQProofInstance{
		X:     x,
		Y:     y,
		Alpha: alpha,
		E:     e,
		F:     f,
	}

	return proof, nil

}

func (pk *PublicKey) verifyDDLEQProofInstance(ct1 *Ciphertext, ct2 *Ciphertext, proof *DDLEQProofInstance) bool {

	// powers of n needed in the protocol
	n := pk.N
	n2 := pk.GetN2()
	n3 := pk.GetN3()

	// Fiat-Shamir heuristic to get a random challenge bit
	// hashdata = c1 || c2 || r2 || s2 || alpha
	chalBit := RandomOracleBit(ct1.C, ct2.C, proof.X, proof.Y, proof.Alpha)

	check := new(gmp.Int).Set(ct1.C)
	if chalBit {
		check.Set(ct2.C)
	}

	en := new(gmp.Int).Exp(proof.E, n, n2)
	fn2 := new(gmp.Int).Exp(proof.F, n2, n3)

	check.Exp(check, en, n3)
	check.Mul(check, fn2)
	check.Mod(check, n3)

	return proof.Alpha.Cmp(check) == 0
}
