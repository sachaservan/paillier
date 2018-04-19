package paillier

import (
	"math/big"
	"reflect"
	"testing"
)

func TestLCM(t *testing.T) {
	a := big.NewInt(2 * 3 * 3 * 3 * 5 * 5)
	b := big.NewInt(3 * 3 * 5 * 5 * 57 * 11)
	exp := big.NewInt(3 * 3 * 5 * 5)
	if reflect.DeepEqual(exp, LCM(a, b)) {
		t.Fail()
	}
}

func TestL(t *testing.T) {
	u := big.NewInt(21)
	n := big.NewInt(3)
	exp := big.NewInt(6)
	if !reflect.DeepEqual(exp, L(u, n)) {
		t.Error("L function is not good")
	}
}

func TestComputeMu(t *testing.T) {
	p := big.NewInt(13)
	q := big.NewInt(11)

	lambda := computeLamda(p, q)
	g := big.NewInt(5000)
	n := new(big.Int).Mul(p, q)

	exp := big.NewInt(3)
	if !reflect.DeepEqual(computeMu(g, lambda, n), exp) {
		t.Error("lambda is not well computed")
	}
}

func TestEncryptDecryptSmall(t *testing.T) {
	p := big.NewInt(13)
	q := big.NewInt(11)
	for i := 1; i < 10; i++ {
		privateKey := CreateSecretKey(p, q)

		ciphertext := privateKey.Encrypt(big.NewInt(100))

		returnedValue := privateKey.Decrypt(ciphertext)
		if !reflect.DeepEqual(big.NewInt(100), returnedValue) {
			t.Error("wrong decryption ", returnedValue, " is not ", big.NewInt(100))
		}
	}

}

func TestAdd(t *testing.T) {
	privateKey := CreateSecretKey(big.NewInt(13), big.NewInt(11))
	pk := privateKey.PublicKey

	ciphertext1 := pk.Encrypt(big.NewInt(12))
	ciphertext2 := pk.Encrypt(big.NewInt(13))

	ciphertext3 := pk.EAdd(ciphertext1, ciphertext2)
	m := privateKey.Decrypt(ciphertext3)
	if !reflect.DeepEqual(m, big.NewInt(25)) {
		t.Error(m)
	}
}
