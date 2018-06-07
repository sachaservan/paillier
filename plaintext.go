package paillier

import (
	"math/big"
)

func (pk *PublicKey) EncodeFixedPoint(a *big.Float, prec int) *big.Int {

	precPow := big.NewFloat(0.0).SetInt(big.NewInt(0).Exp(big.NewInt(2), big.NewInt(int64(prec)), nil))
	scaled := big.NewFloat(0).Mul(a, precPow)

	floor := big.NewInt(0)
	floor, _ = scaled.Int(floor)
	return floor
}
