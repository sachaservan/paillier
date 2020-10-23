package paillier

import (
	"reflect"
	"testing"

	gmp "github.com/ncw/gmp"
)

func TestAdd(t *testing.T) {
	privateKey, _ := KeyGen(10)
	pk := privateKey.PublicKey

	ciphertext1 := pk.Encrypt(gmp.NewInt(12))
	ciphertext2 := pk.Encrypt(gmp.NewInt(13))
	ciphertext3 := pk.Encrypt(gmp.NewInt(14))

	ciphertext4 := pk.Add(ciphertext1, ciphertext2, ciphertext3)
	m := privateKey.Decrypt(ciphertext4)
	if !reflect.DeepEqual(m, gmp.NewInt(39)) {
		t.Error("wrong addition ", m, " is not ", gmp.NewInt(39))
		t.Error(m)
	}
}

func TestSub(t *testing.T) {
	privateKey, _ := KeyGen(10)
	pk := privateKey.PublicKey

	ciphertext1 := pk.Encrypt(gmp.NewInt(20))
	ciphertext2 := pk.Encrypt(gmp.NewInt(10))
	ciphertext3 := pk.Encrypt(gmp.NewInt(5))

	ciphertext4 := pk.Sub(ciphertext1, ciphertext2, ciphertext3)
	m := privateKey.Decrypt(ciphertext4)
	if !reflect.DeepEqual(m, gmp.NewInt(5)) {
		t.Error("wrong subtraction ", m, " is not ", gmp.NewInt(5))
		t.Error(m)
	}
}

func TestMult(t *testing.T) {
	privateKey, _ := KeyGen(10)
	pk := privateKey.PublicKey

	ciphertext1 := pk.Encrypt(gmp.NewInt(40))
	ciphertext2 := pk.ConstMult(ciphertext1, gmp.NewInt(2))
	m := privateKey.Decrypt(ciphertext2)
	if !reflect.DeepEqual(m, gmp.NewInt(80)) {
		t.Error("wrong multiplication ", m, " is not ", gmp.NewInt(80))
		t.Error(m)
	}
}

func BenchmarkAdd(b *testing.B) {
	_, pk := KeyGen(1024)
	c := pk.Encrypt(gmp.NewInt(12))

	for i := 0; i < b.N; i++ {
		pk.Add(c, c)
	}
}

func BenchmarkConstMul(b *testing.B) {
	_, pk := KeyGen(1024)
	c := pk.Encrypt(gmp.NewInt(12))

	for i := 0; i < b.N; i++ {
		pk.ConstMult(c, gmp.NewInt(1))
	}
}
