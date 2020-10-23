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
	if reflect.DeepEqual(exp, lcm(a, b)) {
		t.Fail()
	}
}

func TestL(t *testing.T) {
	u := big.NewInt(21)
	n := big.NewInt(3)
	exp := big.NewInt(6)
	if !reflect.DeepEqual(exp, l(u, n)) {
		t.Error("L function is not good")
	}
}

func TestEncryptDecryptSmall(t *testing.T) {

	for i := 1; i < 1000; i++ {
		sk, _ := KeyGen(10)
		ciphertext := sk.Encrypt(big.NewInt(100))
		returnedValue := sk.Decrypt(ciphertext)
		if !reflect.DeepEqual(big.NewInt(100), returnedValue) {
			t.Error("wrong decryption ", returnedValue, " is not ", big.NewInt(100))
		}
	}
}

func TestAdd(t *testing.T) {
	privateKey, _ := KeyGen(10)
	pk := privateKey.PublicKey

	ciphertext1 := pk.Encrypt(big.NewInt(12))
	ciphertext2 := pk.Encrypt(big.NewInt(13))
	ciphertext3 := pk.Encrypt(big.NewInt(14))

	ciphertext4 := pk.Add(ciphertext1, ciphertext2, ciphertext3)
	m := privateKey.Decrypt(ciphertext4)
	if !reflect.DeepEqual(m, big.NewInt(39)) {
		t.Error("wrong addition ", m, " is not ", big.NewInt(39))
		t.Error(m)
	}
}

func TestSub(t *testing.T) {
	privateKey, _ := KeyGen(10)
	pk := privateKey.PublicKey

	ciphertext1 := pk.Encrypt(big.NewInt(20))
	ciphertext2 := pk.Encrypt(big.NewInt(10))
	ciphertext3 := pk.Encrypt(big.NewInt(5))

	ciphertext4 := pk.Sub(ciphertext1, ciphertext2, ciphertext3)
	m := privateKey.Decrypt(ciphertext4)
	if !reflect.DeepEqual(m, big.NewInt(5)) {
		t.Error("wrong subtraction ", m, " is not ", big.NewInt(5))
		t.Error(m)
	}
}

func TestMult(t *testing.T) {
	privateKey, _ := KeyGen(10)
	pk := privateKey.PublicKey

	ciphertext1 := pk.Encrypt(big.NewInt(40))
	ciphertext2 := pk.ConstMult(ciphertext1, big.NewInt(2))
	m := privateKey.Decrypt(ciphertext2)
	if !reflect.DeepEqual(m, big.NewInt(80)) {
		t.Error("wrong multiplication ", m, " is not ", big.NewInt(80))
		t.Error(m)
	}
}

func BenchmarkDecrypt(b *testing.B) {
	sk, pk := KeyGen(512)
	c := pk.Encrypt(big.NewInt(12))

	for i := 0; i < b.N; i++ {
		Decrypt(c, sk)
	}
}

func BenchmarkEncrypt(b *testing.B) {
	_, pk := KeyGen(512)

	for i := 0; i < b.N; i++ {
		Encrypt(big.NewInt(100), pk)
	}
}

func Decrypt(c *Ciphertext, sk *SecretKey) *big.Int {
	return sk.Decrypt(c)
}

func Encrypt(m *big.Int, pk *PublicKey) *Ciphertext {
	return pk.Encrypt(m)
}
