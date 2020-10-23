package paillier

import (
	"reflect"
	"testing"

	gmp "github.com/ncw/gmp"
)

func TestLCM(t *testing.T) {
	a := gmp.NewInt(2 * 3 * 3 * 3 * 5 * 5)
	b := gmp.NewInt(3 * 3 * 5 * 5 * 57 * 11)
	exp := gmp.NewInt(3 * 3 * 5 * 5)
	if reflect.DeepEqual(exp, lcm(a, b)) {
		t.Fail()
	}
}

func TestL(t *testing.T) {
	u := gmp.NewInt(21)
	n := gmp.NewInt(3)
	exp := gmp.NewInt(6)
	if !reflect.DeepEqual(exp, l(u, n)) {
		t.Error("L function is not good")
	}
}

func TestEncryptDecryptSmall(t *testing.T) {

	for i := 1; i < 1000; i++ {
		sk, _ := KeyGen(10)
		ciphertext := sk.Encrypt(gmp.NewInt(100))
		returnedValue := sk.Decrypt(ciphertext)
		if !reflect.DeepEqual(gmp.NewInt(100), returnedValue) {
			t.Error("wrong decryption ", returnedValue, " is not ", gmp.NewInt(100))
		}
	}
}

func BenchmarkDecrypt(b *testing.B) {
	sk, pk := KeyGen(512)
	c := pk.Encrypt(gmp.NewInt(12))

	for i := 0; i < b.N; i++ {
		Decrypt(c, sk)
	}
}

func BenchmarkEncrypt(b *testing.B) {
	_, pk := KeyGen(512)

	for i := 0; i < b.N; i++ {
		Encrypt(gmp.NewInt(100), pk)
	}
}

func Decrypt(c *Ciphertext, sk *SecretKey) *gmp.Int {
	return sk.Decrypt(c)
}

func Encrypt(m *gmp.Int, pk *PublicKey) *Ciphertext {
	return pk.Encrypt(m)
}
