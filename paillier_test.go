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

func TestEncryptDecryptLevel3(t *testing.T) {

	for i := 1; i < 10; i++ {
		sk, pk := KeyGen(64)
		value := ToBigInt(gmp.NewInt(0).Sub(pk.GetN2(), gmp.NewInt(int64(i))))
		ciphertext := pk.EncryptAtLevel(ToGmpInt(value), EncLevelThree)
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
		ciphertextLevelTwo := pk.EncryptAtLevel(value, EncLevelTwo)
		ciphertextLevelThree := pk.EncryptAtLevel(ciphertextLevelTwo.C, EncLevelThree) // double encryption
		firstDecryption := sk.Decrypt(ciphertextLevelThree)
		firstDecryptionAsLevel2Ciphertext := &Ciphertext{firstDecryption, EncLevelTwo}
		secondDecryption := sk.Decrypt(firstDecryptionAsLevel2Ciphertext)

		returnedValue := ToBigInt(secondDecryption)
		if !reflect.DeepEqual(big.NewInt(int64(i)), returnedValue) {
			t.Error("wrong decryption ", returnedValue, " is not ", value)
		}
	}
}

func TestDoubleEncryptRandomize(t *testing.T) {

	for i := 1; i < 1000; i++ {
		sk, pk := KeyGen(64)
		value := gmp.NewInt(int64(i))
		ciphertextLevelTwo := pk.EncryptAtLevel(value, EncLevelTwo)
		ciphertextLevelThree := pk.EncryptAtLevel(ciphertextLevelTwo.C, EncLevelThree) // double encryption

		randomizedLevelThree := pk.NestedRandomize(ciphertextLevelThree)

		firstDecryption := sk.Decrypt(randomizedLevelThree)
		firstDecryptionAsLevel2Ciphertext := &Ciphertext{firstDecryption, EncLevelTwo}

		if reflect.DeepEqual(ToBigInt(firstDecryptionAsLevel2Ciphertext.C), ToBigInt(ciphertextLevelTwo.C)) {
			t.Error("did not randomized inner ciphertext ", firstDecryptionAsLevel2Ciphertext.C, " is equal to ", ciphertextLevelTwo.C)
		}

		secondDecryption := sk.Decrypt(firstDecryptionAsLevel2Ciphertext)

		returnedValue := ToBigInt(secondDecryption)
		if !reflect.DeepEqual(big.NewInt(int64(i)), returnedValue) {
			t.Error("wrong decryption ", returnedValue, " is not ", value)
		}
	}
}

func TestDoubleEncryptAdd(t *testing.T) {

	for i := 1; i < 1000; i++ {
		sk, pk := KeyGen(64)
		value := gmp.NewInt(int64(i))

		ciphertextLevelTwo := pk.EncryptAtLevel(value, EncLevelTwo)
		ciphertextLevelThree := pk.EncryptAtLevel(ciphertextLevelTwo.C, EncLevelThree) // double encryption

		ciphertextLevelThree = pk.NestedAdd(ciphertextLevelThree, ciphertextLevelTwo) // add the value to itself in the nested encryption

		firstDecryption := sk.Decrypt(ciphertextLevelThree)

		firstDecryptionAsLevel2Ciphertext := &Ciphertext{firstDecryption, EncLevelTwo}
		secondDecryption := sk.Decrypt(firstDecryptionAsLevel2Ciphertext)

		returnedValue := ToBigInt(secondDecryption)
		if !reflect.DeepEqual(big.NewInt(int64(2*i)), returnedValue) {
			t.Error("wrong decryption ", returnedValue, " is not ", value)
		}
	}
}

func TestDoubleEncryptSub(t *testing.T) {

	for i := 1; i < 1000; i++ {
		sk, pk := KeyGen(64)
		value := gmp.NewInt(int64(i))

		ciphertextLevelTwo := pk.EncryptAtLevel(value, EncLevelTwo)
		ciphertextLevelThree := pk.EncryptAtLevel(ciphertextLevelTwo.C, EncLevelThree) // double encryption

		ciphertextLevelThree = pk.NestedSub(ciphertextLevelThree, ciphertextLevelTwo) // add the value to itself in the nested encryption

		firstDecryption := sk.Decrypt(ciphertextLevelThree)

		firstDecryptionAsLevel2Ciphertext := &Ciphertext{firstDecryption, EncLevelTwo}
		secondDecryption := sk.Decrypt(firstDecryptionAsLevel2Ciphertext)

		returnedValue := ToBigInt(secondDecryption)
		if !reflect.DeepEqual(big.NewInt(int64(0)), returnedValue) {
			t.Error("wrong decryption ", returnedValue, " is not ", value)
		}
	}
}

func TestToFromBytes(t *testing.T) {

	for i := 1; i < 1000; i++ {
		_, pk := KeyGen(10)
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
