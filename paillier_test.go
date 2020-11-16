package paillier

import (
	"math/big"
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
	if !reflect.DeepEqual(exp, L(u, n)) {
		t.Error("L function is not good")
	}
}

func TestGenerators(t *testing.T) {

	sk, pk := KeyGen(64)

	n2 := pk.GetN2()
	n3 := pk.GetN2()

	h1 := pk.getGeneratorOfQuadraticResiduesForLevel(EncLevelOne)
	h2 := pk.getGeneratorOfQuadraticResiduesForLevel(EncLevelTwo)

	resL1 := new(gmp.Int).Exp(h1, sk.Lambda, n2)
	resL2 := new(gmp.Int).Exp(h2, sk.Lambda, n3)

	if !reflect.DeepEqual(big.NewInt(1), ToBigInt(resL1)) {
		t.Error("h1 is not a valid generator h_1^n = ", resL1, ", should be 1")
	}

	if !reflect.DeepEqual(big.NewInt(1), ToBigInt(resL2)) {
		t.Error("h1 is not a valid generator h_2^n = ", resL2, ", should be 1")
	}

}

func TestEncryptDecrypt(t *testing.T) {

	for i := 1; i < 1000; i++ {
		sk, pk := KeyGen(64)
		value := gmp.NewInt(int64(i))
		ciphertext := pk.Encrypt(value)
		returnedValue := ToBigInt(sk.Decrypt(ciphertext))
		if !reflect.DeepEqual(big.NewInt(int64(i)), returnedValue) {
			t.Error("wrong decryption ", returnedValue, " is not ", value)
		}
	}
}

func TestNestedEncryptDecrypt(t *testing.T) {

	for i := 1; i < 1000; i++ {
		sk, pk := KeyGen(64)
		value := gmp.NewInt(int64(i))
		ciphertext := pk.NestedEncrypt(value)
		returnedValue := ToBigInt(sk.NestedDecrypt(ciphertext))
		if !reflect.DeepEqual(big.NewInt(int64(i)), returnedValue) {
			t.Error("wrong decryption ", returnedValue, " is not ", value)
		}
	}
}

func TestEncryptDecryptLevel2(t *testing.T) {

	for i := 1; i < 10; i++ {
		sk, pk := KeyGen(64)
		value := ToBigInt(gmp.NewInt(0).Sub(pk.GetN2(), gmp.NewInt(int64(i))))
		ciphertext := pk.EncryptAtLevel(ToGmpInt(value), EncLevelTwo)
		returnedValue := ToBigInt(sk.Decrypt(ciphertext))

		if !reflect.DeepEqual(value, returnedValue) {
			t.Error("wrong decryption ", returnedValue, " is not ", value)
		}
	}
}

func TestDoubleEncryptDecrypt(t *testing.T) {

	for i := 1; i < 1000; i++ {
		sk, pk := KeyGen(64)
		value := gmp.NewInt(int64(i))
		ciphertextLevelOne := pk.EncryptAtLevel(value, EncLevelOne)
		ciphertextLevelTwo := pk.EncryptAtLevel(ciphertextLevelOne.C, EncLevelTwo) // double encryption
		firstDecryption := sk.Decrypt(ciphertextLevelTwo)
		firstDecryptionAsLevel2Ciphertext := &Ciphertext{firstDecryption, EncLevelOne, RegularEncryption}
		secondDecryption := sk.Decrypt(firstDecryptionAsLevel2Ciphertext)

		returnedValue := ToBigInt(secondDecryption)
		if !reflect.DeepEqual(big.NewInt(int64(i)), returnedValue) {
			t.Error("wrong decryption ", returnedValue, " is not ", value)
		}
	}
}

func TestDecryptNestedCiphertext(t *testing.T) {

	for i := 1; i < 1000; i++ {
		sk, pk := KeyGen(64)
		value := gmp.NewInt(int64(i))
		ciphertextLevelOne := pk.EncryptAtLevel(value, EncLevelOne)
		ciphertextLevelTwo := pk.EncryptAtLevel(ciphertextLevelOne.C, EncLevelTwo) // double encryption
		firstDecryption := sk.DecryptNestedCiphertextLayer(ciphertextLevelTwo)
		secondDecryption := sk.Decrypt(firstDecryption)

		returnedValue := ToBigInt(secondDecryption)
		if !reflect.DeepEqual(big.NewInt(int64(i)), returnedValue) {
			t.Error("wrong decryption ", returnedValue, " is not ", value)
		}
	}
}

func TestToFromBytes(t *testing.T) {

	for i := 1; i < 1000; i++ {
		_, pk := KeyGen(64)
		ciphertext := pk.Encrypt(gmp.NewInt(100))
		ctBytes := ciphertext.Bytes()
		ctRecoverd, err := pk.NewCiphertextFromBytes(ctBytes)

		if err != nil {
			t.Error(err)
		}

		if !reflect.DeepEqual(ctRecoverd, ciphertext) {
			t.Error("recovered from bytes ", ctRecoverd, " is not original ", ciphertext)
		}
	}
}

func BenchmarkDecrypt(b *testing.B) {
	sk, pk := KeyGen(1024)
	c := pk.Encrypt(gmp.NewInt(12))

	for i := 0; i < b.N; i++ {
		Decrypt(c, sk)
	}
}

func BenchmarkEncrypt(b *testing.B) {
	_, pk := KeyGen(1024)

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
