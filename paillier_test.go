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

func TestEncryptDecryptSmall(t *testing.T) {

	for i := 1; i < 10; i++ {
		privateKey := CreateSecretKey(10)

		ciphertext := privateKey.Encrypt(big.NewInt(100))

		returnedValue := privateKey.Decrypt(ciphertext)
		if !reflect.DeepEqual(big.NewInt(100), returnedValue) {
			t.Error("wrong decryption ", returnedValue, " is not ", big.NewInt(100))
		}
	}

}

func TestAdd(t *testing.T) {
	privateKey := CreateSecretKey(10)
	pk := privateKey.PublicKey

	ciphertext1 := pk.Encrypt(big.NewInt(12))
	ciphertext2 := pk.Encrypt(big.NewInt(13))

	ciphertext3 := pk.EAdd(ciphertext1, ciphertext2)
	m := privateKey.Decrypt(ciphertext3)
	if !reflect.DeepEqual(m, big.NewInt(25)) {
		t.Error(m)
	}
}
