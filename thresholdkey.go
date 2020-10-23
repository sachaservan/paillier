package paillier

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"

	gmp "github.com/ncw/gmp"
)

// ThresholdPublicKey for the threshold Paillier scheme
//
// `V` is a generator in  the cyclic group of squares Z_n^2 and is used to
// execute a zero-knowledge proof of a received share decryption.
//
// `Vi` is an array of verification keys for each decryption server `i` used to
// execute a zero-knowledge proof of a received share decryption.
//
// Key generation, encryption, share decryption and combining for the threshold
// Paillier scheme has been described in [DJN 10], section 5.1.
//
//     [DJN 10]: Ivan Damgard, Mads Jurik, Jesper Buus Nielsen, (2010)
//               A Generalization of Paillier’s Public-Key System
//               with Applications to Electronic Voting
//               Aarhus University, Dept. of Computer Science, BRICS
type ThresholdPublicKey struct {
	PublicKey
	TotalNumberOfDecryptionServers int
	Threshold                      int
	VerificationKey                *gmp.Int // needed for ZKP
	VerificationKeys               []*gmp.Int
}

// ThresholdSecretKey is the key for a threshold Paillier scheme.
// Holds private information for the given decryption server.
// `ID` is the unique identifier of a decryption server and `Share` is a secret
// share generated from hiding polynomial and is used for a partial share decryption.
type ThresholdSecretKey struct {
	ThresholdPublicKey
	ID    int
	Share *gmp.Int
}

// PartialDecryption contains a partially decrypted ciphertext
type PartialDecryption struct {
	ID         int
	Decryption *gmp.Int
}

// PartialDecryptionZKP is a non-interactive ZKP based on the Fiat–Shamir heuristic
// used to prove that a ciphertext was decrypted correctly under a partial decryption key
type PartialDecryptionZKP struct {
	PartialDecryption
	Key *ThresholdPublicKey // the public key used to encrypt
	E   *gmp.Int            // the challenge
	Z   *gmp.Int            // the value needed to check to verify the decryption
	C   *gmp.Int            // the input cypher text
}

// Returns the value of [(4*delta^2)]^-1  mod n.
// It is a constant value for the given `ThresholdKey` and is used in the last
// step of share combining.
func (tk *ThresholdPublicKey) combineSharesConstant() *gmp.Int {
	tmp := new(gmp.Int).Mul(FourBigInt, new(gmp.Int).Mul(tk.delta(), tk.delta()))
	return (&gmp.Int{}).ModInverse(tmp, tk.N)
}

// Returns the factorial of the number of `TotalNumberOfDecryptionServers`.
// It is a contant value for the given `ThresholdKey`.
func (tk *ThresholdPublicKey) delta() *gmp.Int {
	return Factorial(tk.TotalNumberOfDecryptionServers)
}

// Checks if the number of received, unique shares is less than the
// required threshold.
// This method does not execute ZKP on received shares.
func (tk *ThresholdPublicKey) verifyPartialDecryptions(shares []*PartialDecryption) error {
	if len(shares) < tk.Threshold {
		return errors.New("Threshold not meet")
	}
	tmp := make(map[int]bool)
	for _, share := range shares {
		tmp[share.ID] = true
	}
	if len(tmp) != len(shares) {
		return errors.New("two shares has been created by the same server")
	}
	return nil
}

func (tk *ThresholdPublicKey) updateLambda(share1, share2 *PartialDecryption, lambda *gmp.Int) *gmp.Int {
	num := new(gmp.Int).Mul(lambda, gmp.NewInt(int64(-share2.ID)))
	denom := gmp.NewInt(int64(share1.ID - share2.ID))
	return new(gmp.Int).Div(num, denom)
}

// Evaluates lambda parameter for each decrypted share. See second figure in the
// "Share combining" paragraph in [DJK 10], section 5.2.
func (tk *ThresholdPublicKey) computeLambda(share *PartialDecryption, shares []*PartialDecryption) *gmp.Int {
	lambda := tk.delta()
	for _, share2 := range shares {
		if share2.ID != share.ID {
			lambda = tk.updateLambda(share, share2, lambda)
		}
	}
	return lambda
}

// Used to evaluate c' parameter which combines individual share decryptions.
//
// Modulo division is performed on the computed exponent to avoid creating
// large numbers. This is possible because of the following property of modulo:
// A^B mod C = (A mod C)^B mod C
//
// Modulo division is performed on the computed coefficient because of the
// following property of modulo:
// (AB) mod C = (A mod C * B mod C) mod C
// Note, we need to combine coefficients into single c'.
func (tk *ThresholdPublicKey) updateCprime(cprime, lambda *gmp.Int, share *PartialDecryption) *gmp.Int {
	twoLambda := new(gmp.Int).Mul(TwoBigInt, lambda)
	ret := tk.exp(share.Decryption, twoLambda, tk.GetN2())
	ret = new(gmp.Int).Mul(cprime, ret)
	return new(gmp.Int).Mod(ret, tk.GetN2())
}

// We use `exp` from `updateCprime` to raise decryption share to the power of lambda
// parameter. Since lambda can be a negative number and we do discrete math here,
// we need to apply multiplicative inverse modulo in this case.
//
// For instance, for b = -18:
// b^{−18} = (b^−1)^18, where b^{−1} is the multiplicative inverse modulo c.
func (tk *ThresholdPublicKey) exp(a, b, c *gmp.Int) *gmp.Int {
	if b.Cmp(ZeroBigInt) == -1 { // b < 0 ?
		ret := new(gmp.Int).Exp(a, new(gmp.Int).Neg(b), c)
		return new(gmp.Int).ModInverse(ret, c)
	}
	return new(gmp.Int).Exp(a, b, c)
}

// Executes the last step of message decryption. Takes `cprime` value computed
// from valid shares provided by decryption servers and multiplies this value
// by `combineSharesContant` which is specific to the given public `ThresholdKey`.
func (tk *ThresholdPublicKey) computeDecryption(cprime *gmp.Int) *gmp.Int {
	l := l(cprime, tk.N)
	return new(gmp.Int).Mod(new(gmp.Int).Mul(tk.combineSharesConstant(), l), tk.N)
}

// CombinePartialDecryptions merges several partial decryptions to produce a plaintext
func (tk *ThresholdPublicKey) CombinePartialDecryptions(shares []*PartialDecryption) (*gmp.Int, error) {
	if err := tk.verifyPartialDecryptions(shares); err != nil {
		return nil, err
	}

	cprime := OneBigInt
	for _, share := range shares {
		lambda := tk.computeLambda(share, shares)
		cprime = tk.updateCprime(cprime, lambda, share)
	}

	return tk.computeDecryption(cprime), nil
}

// CombinePartialDecryptionsZKP merges several ZKP for partial decryptions
func (tk *ThresholdPublicKey) CombinePartialDecryptionsZKP(shares []*PartialDecryptionZKP) (*gmp.Int, error) {
	ret := make([]*PartialDecryption, 0)
	for _, share := range shares {
		if share.VerifyProof() {
			ret = append(ret, &share.PartialDecryption)
		}
	}
	return tk.CombinePartialDecryptions(ret)
}

// VerifyDecryption checks if the partial decryption was performed correctly; returns error if not
func (tk *ThresholdPublicKey) VerifyDecryption(encryptedMessage, decryptedMessage *gmp.Int, shares []*PartialDecryptionZKP) error {
	for _, share := range shares {
		if share.C.Cmp(encryptedMessage) != 0 {
			return errors.New("The encrypted message is not the same than the one in the shares")
		}
	}
	res, err := tk.CombinePartialDecryptionsZKP(shares)
	if err != nil {
		return err
	}
	if res.Cmp(decryptedMessage) != 0 {
		return errors.New("The decrypted message is not the same than the one in the shares")
	}
	return nil
}

// PartialDecrypt returns the partial decryption of the ciphertext
func (tsk *ThresholdSecretKey) PartialDecrypt(c *gmp.Int) *PartialDecryption {
	ret := new(PartialDecryption)
	ret.ID = tsk.ID
	exp := new(gmp.Int).Mul(tsk.Share, new(gmp.Int).Mul(TwoBigInt, tsk.delta()))
	gmpExp := gmp.NewInt(0).SetBytes(exp.Bytes())
	gmpC := gmp.NewInt(0).SetBytes(c.Bytes())
	gmpN2 := gmp.NewInt(0).SetBytes(tsk.GetN2().Bytes())
	ret.Decryption = gmp.NewInt(0).SetBytes(new(gmp.Int).Exp(gmpC, gmpExp, gmpN2).Bytes())
	return ret
}

func (tsk *ThresholdSecretKey) copyVerificationKeys() []*gmp.Int {
	ret := make([]*gmp.Int, len(tsk.VerificationKeys))
	for i, vi := range tsk.VerificationKeys {
		ret[i] = new(gmp.Int).Add(vi, gmp.NewInt(0))
	}
	return ret
}

// PublicKey returns the threshold public key associated with the
// threshold secret key tsk
func (tsk *ThresholdSecretKey) PublicKey() *ThresholdPublicKey {
	ret := new(ThresholdPublicKey)
	ret.Threshold = tsk.Threshold
	ret.TotalNumberOfDecryptionServers = tsk.TotalNumberOfDecryptionServers
	ret.VerificationKey = tsk.VerificationKey
	ret.VerificationKeys = tsk.copyVerificationKeys()
	ret.N = new(gmp.Int).Add(tsk.N, gmp.NewInt(0))
	return ret
}

// PartialDecryptionWithZKP produces a partial decryption of the ciphertext
// along with a zero-knowledge proof that it was performed correctly.
func (tsk *ThresholdSecretKey) PartialDecryptionWithZKP(c *gmp.Int) (*PartialDecryptionZKP, error) {
	pd := new(PartialDecryptionZKP)
	pd.Key = tsk.PublicKey()
	pd.C = c
	pd.ID = tsk.ID
	pd.Decryption = tsk.PartialDecrypt(c).Decryption

	// choose random number
	rBig, err := rand.Int(rand.Reader, tsk.GetN2AsBigInt())
	if err != nil {
		return nil, err
	}

	r := new(gmp.Int).SetBytes(rBig.Bytes())

	//  compute a
	c4 := new(gmp.Int).Exp(c, FourBigInt, nil)
	a := new(gmp.Int).Exp(c4, r, tsk.GetN2())

	// compute b
	b := new(gmp.Int).Exp(tsk.VerificationKey, r, tsk.GetN2())

	// compute hash
	ci2 := new(gmp.Int).Exp(pd.Decryption, gmp.NewInt(2), nil)

	pd.E = tsk.computeHash(a, b, c4, ci2)

	pd.Z = tsk.computeZ(r, pd.E)

	return pd, nil
}

// VerifyPartialDecryption checks if the partial decryption is valid
func (tsk *ThresholdSecretKey) VerifyPartialDecryption() error {
	m, err := rand.Int(rand.Reader, ToBigInt(tsk.N))
	if err != nil {
		return err
	}
	c := tsk.Encrypt(ToGmpInt(m))
	if err != nil {
		return err
	}
	proof, err := tsk.PartialDecryptionWithZKP(c.C)
	if err != nil {
		return err
	}
	if !proof.VerifyProof() {
		return errors.New("Invalid share")
	}
	return nil
}

// VerifyProof returns true if and only if the proof is correct
func (pd *PartialDecryptionZKP) VerifyProof() bool {
	a := pd.verifyPart1()
	b := pd.verifyPart2()
	hash := sha256.New()
	hash.Write(a.Bytes())
	hash.Write(b.Bytes())
	c4 := new(gmp.Int).Exp(pd.C, FourBigInt, nil)
	hash.Write(c4.Bytes())
	ci2 := new(gmp.Int).Exp(pd.Decryption, TwoBigInt, nil)
	hash.Write(ci2.Bytes())

	expectedE := new(gmp.Int).SetBytes(hash.Sum([]byte{}))
	return pd.E.Cmp(expectedE) == 0
}

func (pd *PartialDecryptionZKP) verifyPart1() *gmp.Int {
	c4 := new(gmp.Int).Exp(pd.C, FourBigInt, nil)                  // c^4
	decryption2 := new(gmp.Int).Exp(pd.Decryption, TwoBigInt, nil) // c_i^2

	a1 := new(gmp.Int).Exp(c4, pd.Z, pd.Key.GetN2())          // (c^4)^Z
	a2 := new(gmp.Int).Exp(decryption2, pd.E, pd.Key.GetN2()) // (c_i^2)^E
	a2 = new(gmp.Int).ModInverse(a2, pd.Key.GetN2())
	a := new(gmp.Int).Mod(new(gmp.Int).Mul(a1, a2), pd.Key.GetN2())
	return a
}

func (pd *PartialDecryptionZKP) verifyPart2() *gmp.Int {
	vi := pd.Key.VerificationKeys[pd.ID-1]                               // servers are indexed from 1
	b1 := new(gmp.Int).Exp(pd.Key.VerificationKey, pd.Z, pd.Key.GetN2()) // V^Z
	b2 := new(gmp.Int).Exp(vi, pd.E, pd.Key.GetN2())                     // (v_i)^E
	b2 = new(gmp.Int).ModInverse(b2, pd.Key.GetN2())
	b := new(gmp.Int).Mod(new(gmp.Int).Mul(b1, b2), pd.Key.GetN2())
	return b
}

func (tsk *ThresholdSecretKey) computeZ(r, e *gmp.Int) *gmp.Int {
	tmp := new(gmp.Int).Mul(e, tsk.delta())
	tmp = new(gmp.Int).Mul(tmp, tsk.Share)
	return new(gmp.Int).Add(r, tmp)
}

func (tsk *ThresholdSecretKey) computeHash(a, b, c4, ci2 *gmp.Int) *gmp.Int {
	hash := sha256.New()
	hash.Write(a.Bytes())
	hash.Write(b.Bytes())
	hash.Write(c4.Bytes())
	hash.Write(ci2.Bytes())
	return new(gmp.Int).SetBytes(hash.Sum([]byte{}))
}
