package paillier

import (
	"crypto/sha256"

	gmp "github.com/ncw/gmp"
)

// RandomOracleBit hashes the input bytes to produce a bit (true/false)
func RandomOracleBit(values ...*gmp.Int) bool {

	res := RandomOracleDigest(values...)
	bit := new(gmp.Int).SetBytes(res[:])
	bit.Mod(bit, gmp.NewInt(2)) // extract a random bit
	return bit.Cmp(OneBigInt) == 0
}

// RandomOracleDigest returns the digest of all the input bytes
// using SHA 256 to model a random oracle
func RandomOracleDigest(values ...*gmp.Int) []byte {

	hashData := make([]byte, 0)
	for i, b := range values {
		if i == 0 {
			continue
		}
		hashData = append(hashData, b.Bytes()...)
	}

	res := sha256.Sum256(hashData)
	return res[:]
}
