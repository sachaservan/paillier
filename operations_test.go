package paillier

import (
	"math/big"
	"reflect"
	"testing"

	gmp "github.com/ncw/gmp"
)

func TestAdd(t *testing.T) {
	privateKey, _ := KeyGen(64)
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
	privateKey, _ := KeyGen(64)
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
	privateKey, _ := KeyGen(64)
	pk := privateKey.PublicKey

	ciphertext1 := pk.Encrypt(gmp.NewInt(40))
	ciphertext2 := pk.ConstMult(ciphertext1, gmp.NewInt(2))
	m := privateKey.Decrypt(ciphertext2)
	if !reflect.DeepEqual(m, gmp.NewInt(80)) {
		t.Error("wrong multiplication ", m, " is not ", gmp.NewInt(80))
		t.Error(m)
	}
}

func TestDoubleEncryptAdd(t *testing.T) {

	sk, pk := KeyGen(64)

	for i := 1; i < 1000; i++ {
		value := gmp.NewInt(int64(i))
		ciphertextLevelOne := pk.EncryptAtLevel(value, EncLevelOne)
		ciphertextLevelTwo := pk.EncryptAtLevel(ciphertextLevelOne.C, EncLevelTwo) // double encryption

		ciphertextLevelTwo = pk.NestedAdd(ciphertextLevelTwo, ciphertextLevelOne) // add the value to itself in the nested encryption

		firstDecryption := sk.Decrypt(ciphertextLevelTwo)

		firstDecryptionAsLevelOneCiphertext := &Ciphertext{firstDecryption, EncLevelOne, ciphertextLevelOne.EncMethod}
		secondDecryption := sk.Decrypt(firstDecryptionAsLevelOneCiphertext)

		returnedValue := ToBigInt(secondDecryption)
		if !reflect.DeepEqual(big.NewInt(int64(2*i)), returnedValue) {
			t.Error("wrong decryption ", returnedValue, " is not ", value)
		}
	}
}

func TestDoubleEncryptSub(t *testing.T) {

	sk, pk := KeyGen(64)

	for i := 1; i < 1000; i++ {
		value := gmp.NewInt(int64(i))
		ciphertextLevelOne := pk.EncryptAtLevel(value, EncLevelOne)
		ciphertextLevelTwo := pk.EncryptAtLevel(ciphertextLevelOne.C, EncLevelTwo) // double encryption

		ciphertextLevelTwo = pk.NestedSub(ciphertextLevelTwo, ciphertextLevelOne) // add the value to itself in the nested encryption

		firstDecryption := sk.Decrypt(ciphertextLevelTwo)

		firstDecryptionAsLevelOneCiphertext := &Ciphertext{firstDecryption, EncLevelOne, RegularEncryption}
		secondDecryption := sk.Decrypt(firstDecryptionAsLevelOneCiphertext)

		returnedValue := ToBigInt(secondDecryption)
		if !reflect.DeepEqual(big.NewInt(int64(0)), returnedValue) {
			t.Error("wrong decryption ", returnedValue, " is not ", value)
		}
	}
}

func TestDoubleEncryptRandomize(t *testing.T) {

	sk, pk := KeyGen(64)

	for i := 1; i < 1000; i++ {

		value := gmp.NewInt(int64(i))
		ciphertextLevelOne := pk.EncryptAtLevel(value, EncLevelOne)
		ciphertextLevelTwo := pk.EncryptAtLevel(ciphertextLevelOne.C, EncLevelTwo) // double encryption

		randomizedLevelTwo, _, _ := pk.NestedRandomize(ciphertextLevelTwo)

		firstDecryption := sk.Decrypt(randomizedLevelTwo)
		firstDecryptionAsLevelTwoCiphertext := &Ciphertext{firstDecryption, EncLevelOne, RegularEncryption}

		if reflect.DeepEqual(ToBigInt(firstDecryptionAsLevelTwoCiphertext.C), ToBigInt(ciphertextLevelTwo.C)) {
			t.Error("did not randomized inner ciphertext ", firstDecryptionAsLevelTwoCiphertext.C, " is equal to ", ciphertextLevelTwo.C)
		}

		secondDecryption := sk.Decrypt(firstDecryptionAsLevelTwoCiphertext)

		returnedValue := ToBigInt(secondDecryption)
		if !reflect.DeepEqual(big.NewInt(int64(i)), returnedValue) {
			t.Error("wrong decryption ", returnedValue, " is not ", value)
		}
	}
}

func TestExtractRandomnessWithRegularEncryption(t *testing.T) {

	sk, pk := KeyGen(64)

	// make sure randomness extracted correctly for level 1 ciphertexts
	for i := 1; i < 1000; i++ {

		value := gmp.NewInt(int64(i))
		rand := gmp.NewInt(int64(i * i))

		ciphertextLevelOne := pk.EncryptWithRAtLevel(value, rand, EncLevelOne)
		got := sk.ExtractRandonness(ciphertextLevelOne)
		expected := rand

		if !reflect.DeepEqual(ToBigInt(got), ToBigInt(expected)) {
			t.Error("extracted randomness not correct. Got: ", got, " expected: ", expected)
		}
	}

	// make sure randomness extracted correctly for level 1 ciphertexts
	for i := 1; i < 1000; i++ {

		value := gmp.NewInt(int64(i))
		rand := gmp.NewInt(int64(i * i))

		ciphertextLevelTwo := pk.EncryptWithRAtLevel(value, rand, EncLevelTwo)
		got := sk.ExtractRandonness(ciphertextLevelTwo)
		expected := rand

		if !reflect.DeepEqual(ToBigInt(got), ToBigInt(expected)) {
			t.Error("extracted randomness not correct. Got: ", got, " expected: ", expected)
		}
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
	s := gmp.NewInt(5)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		pk.ConstMult(c, s)
	}
}
