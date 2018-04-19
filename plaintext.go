package paillier

import (
	"math/big"
)

// Plaintext struct holds data related to the polynomial encoded plaintext
type Plaintext struct {
	Pk          *PublicKey
	Value       *big.Int
	ScaleFactor int
}

// NewPlaintext generates an balanced base b encoded polynomial representation of m
// fpp is the starting floating point scale factor which determines the precision
func (pk *PublicKey) NewPlaintext(m *big.Float) *Plaintext {

	return &Plaintext{pk, pk.EncodeFixedPoint(m, pk.FPPrecBits), 0}
}

func (pk *PublicKey) EncodeFixedPoint(a *big.Float, prec int) *big.Int {

	precPow := big.NewFloat(0.0).SetInt(big.NewInt(0).Exp(big.NewInt(2), big.NewInt(int64(prec)), nil))
	scaled := big.NewFloat(0).Mul(a, precPow)

	floor := big.NewInt(0)
	floor, _ = scaled.Int(floor)
	return floor
}

func (p *Plaintext) String() string {

	power := big.NewInt(0).Exp(big.NewInt(2), big.NewInt(int64(p.ScaleFactor)), nil)
	powerFl := big.NewFloat(0.0).SetInt(power)
	value := big.NewFloat(0.0).SetInt(p.Value)
	value = value.Quo(value, powerFl)

	return value.String()
	//return fmt.Sprintf("%d/%d^%d", p.Value, p.Pk.FPScaleBase, p.ScaleFactor)
}