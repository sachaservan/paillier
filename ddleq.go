package paillier

import (
	"crypto/rand"

	gmp "github.com/ncw/gmp"
)

// DDLEQProof provides a proof that two ciphertexts
// are "nested re-encryptions" of one another
type DDLEQProof struct {
	X, Y, Alpha, E, F *gmp.Int
}

// ProveDDLEQ proves the following relation between ciphertexts
// ct2 = (ct1^a) * b  &  Dec(Dec(ct1)) == Dec(Dec(ct2))
// that is, ct2 is a "double re-encryption" of ct1
// for this to protocol to work, ct2 must be generated using NestedRandomize function.
// The resulting proof can be verified (non-interactively in the ROM) using VerifyDDLEQProof
func (sk *SecretKey) ProveDDLEQ(ct1, ct2 *Ciphertext, a, b *gmp.Int) (*DDLEQProof, error) {

	// powers of n needed in the protocol
	n := sk.N
	n2 := sk.GetN2()
	n3 := sk.GetN3()

	// generators for randomness
	h1 := sk.getGeneratorOfQuadraticResiduesForLevel(EncLevelOne)

	sanityCheck := new(gmp.Int).Set(ct1.C)
	sanityCheck.Exp(sanityCheck, new(gmp.Int).Exp(h1, a, n2), n3)
	sanityCheck.Mul(sanityCheck, new(gmp.Int).Exp(b, n2, n3))
	sanityCheck.Mod(sanityCheck, n3)

	if sanityCheck.Cmp(ct2.C) != 0 {
		panic("cannot prove re-encryption because inputs are wrong")
	}

	bound1 := new(gmp.Int).Mul(n, sk.K)
	x, err := GetRandomNumber(bound1, rand.Reader)
	if err != nil {
		return nil, err
	}

	y, err := GetRandomNumberInMultiplicativeGroup(n, rand.Reader)
	if err != nil {
		return nil, err
	}

	hx := new(gmp.Int).Exp(h1, x, n2)
	yn2 := new(gmp.Int).Exp(y, n2, n3)

	// alpha = c^{h^x} * y^{n^2}
	alpha := new(gmp.Int).Exp(ct1.C, hx, n3)
	alpha.Mul(alpha, yn2)
	alpha.Mod(alpha, n3)

	// Fiat-Shamir heuristic to get a random challenge bit
	// hashdata = c1 || c2 || r2 || s2 || alpha
	chalBit := RandomOracleBit(ct1.C, ct2.C, x, y, alpha)

	// e = x - chalBit * a
	e := new(gmp.Int).Set(x)
	if chalBit {
		e.Sub(e, a)
		e.Mod(e, sk.Lambda)
	}

	f := new(gmp.Int).Set(y)
	if chalBit {
		s := sk.ExtractRandonness(ct1)
		he := new(gmp.Int).Exp(h1, e, n2)

		c := new(gmp.Int).Exp(s, new(gmp.Int).Exp(h1, a, n2), n3)
		c.Mul(c, b)
		c.Exp(c, he, n3)
		c.ModInverse(c, n3)
		c.Mul(c, new(gmp.Int).Exp(s, hx, n3))
		f.Mul(f, c)
	}

	proof := &DDLEQProof{
		X:     x,
		Y:     y,
		Alpha: alpha,
		E:     e,
		F:     f,
	}

	return proof, nil

}

// VerifyDDLEQProof checks if the provided proof is valid for the ciphertexts
// the verification is done non-interactively and has soundness 1/2
func (pk *PublicKey) VerifyDDLEQProof(ct1 *Ciphertext, ct2 *Ciphertext, proof *DDLEQProof) bool {

	// powers of n needed in the protocol
	n2 := pk.GetN2()
	n3 := pk.GetN3()

	// Fiat-Shamir heuristic to get a random challenge bit
	// hashdata = c1 || c2 || r2 || s2 || alpha
	chalBit := RandomOracleBit(ct1.C, ct2.C, proof.X, proof.Y, proof.Alpha)

	check := ct1.C
	if chalBit {
		check = ct2.C
	}

	// generators for randomness
	h1 := pk.getGeneratorOfQuadraticResiduesForLevel(EncLevelOne)

	he := new(gmp.Int).Exp(h1, proof.E, n2)
	fn2 := new(gmp.Int).Exp(proof.F, n2, n3)

	check.Exp(check, he, n3)
	check.Mul(check, fn2)
	check.Mod(check, n3)

	return proof.Alpha.Cmp(check) == 0
}
