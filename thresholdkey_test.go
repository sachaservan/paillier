package paillier

import (
	"crypto/rand"
	"math/big"
	"reflect"
	"testing"
)

func getThresholdPrivateKey() *ThresholdSecretKey {
	tkh, err := NewThresholdKeyGenerator(32, 10, 6, rand.Reader)
	if err != nil {
		panic(err)
	}

	tpks, err := tkh.GenerateKeys()
	if err != nil {
		panic(err)
	}
	return tpks[6]
}

func TestDelta(t *testing.T) {
	tk := new(ThresholdPublicKey)
	tk.TotalNumberOfDecryptionServers = 6
	if delta := tk.delta(); 720 != n(delta) {
		t.Error("Delta is not 720 but", delta)
	}
}

func TestExp(t *testing.T) {
	tk := new(ThresholdPublicKey)

	if exp := tk.exp(big.NewInt(720), big.NewInt(10), big.NewInt(49)); 43 != n(exp) {
		t.Error("Unexpected exponent. Expected 43 but got", exp)
	}

	if exp := tk.exp(big.NewInt(720), big.NewInt(0), big.NewInt(49)); 1 != n(exp) {
		t.Error("Unexpected exponent. Expected 0 but got", exp)
	}

	if exp := tk.exp(big.NewInt(720), big.NewInt(-10), big.NewInt(49)); 8 != n(exp) {
		t.Error("Unexpected exponent. Expected 8 but got", exp)
	}
}

func TestCombineSharesConstant(t *testing.T) {
	tk := new(ThresholdPublicKey)
	tk.N = big.NewInt(101 * 103)
	tk.TotalNumberOfDecryptionServers = 6

	if c := tk.combineSharesConstant(); !reflect.DeepEqual(big.NewInt(4558), c) {
		t.Error("wrong combined key.  ", c)
	}
}

func TestDecrypt(t *testing.T) {
	key := new(ThresholdSecretKey)
	key.TotalNumberOfDecryptionServers = 10
	key.N = b(101 * 103)
	key.Share = b(862)
	key.ID = 9
	c := b(56)

	partial := key.PartialDecrypt(c)

	if partial.ID != 9 {
		t.Fail()
	}
	if n(partial.Decryption) != 40644522 {
		t.Error("wrong decryption ", partial.Decryption)
	}
}

func TestCopyVi(t *testing.T) {
	key := new(ThresholdSecretKey)
	key.VerificationKeys = []*big.Int{b(34), b(2), b(29)}
	vi := key.copyVerificationKeys()
	if !reflect.DeepEqual(vi, key.VerificationKeys) {
		t.Fail()
	}
	key.VerificationKeys[1] = b(89)
	if reflect.DeepEqual(vi, key.VerificationKeys) {
		t.Fail()
	}
}

func TestDecryptWithThresholdKey(t *testing.T) {
	pd := getThresholdPrivateKey()
	c := pd.Encrypt(big.NewInt(876))
	pd.PartialDecrypt(c.C)
}

func TestVerifyPart1(t *testing.T) {
	pd := new(PartialDecryptionZKP)
	pd.Key = new(ThresholdPublicKey)
	pd.Key.N = b(131)
	pd.Decryption = b(101)
	pd.C = b(99)
	pd.E = b(112)
	pd.Z = b(88)

	if a := pd.verifyPart1(); n(a) != 11986 {
		t.Error("wrong a ", a)
	}
}

func TestVerifyPart2(t *testing.T) {
	pd := new(PartialDecryptionZKP)
	pd.Key = new(ThresholdPublicKey)
	pd.ID = 1
	pd.Key.VerificationKeys = []*big.Int{b(77), b(67)} // vi is 67
	pd.Key.N = b(131)
	pd.Key.VerificationKey = b(101)
	pd.E = b(112)
	pd.Z = b(88)
	if b := pd.verifyPart2(); n(b) != 14602 {
		t.Error("wrong b ", b)
	}
}

func TestPartialDecryptionWithZKP(t *testing.T) {
	pd := getThresholdPrivateKey()
	c := pd.Encrypt(big.NewInt(876))

	ZKP, err := pd.PartialDecryptionWithZKP(c.C)
	if err != nil {
		t.Error(err)
	}

	if !ZKP.VerifyProof() {
		t.Fail()
	}
}

func TestMakeVerificationBeforeCombiningPartialDecryptions(t *testing.T) {
	tk := new(ThresholdPublicKey)
	tk.Threshold = 2
	if tk.verifyPartialDecryptions([]*PartialDecryption{}) == nil {
		t.Fail()
	}
	prms := []*PartialDecryption{new(PartialDecryption), new(PartialDecryption)}
	prms[1].ID = 1
	if tk.verifyPartialDecryptions(prms) != nil {
		t.Fail()
	}
	prms[1].ID = 0
	if tk.verifyPartialDecryptions(prms) == nil {
		t.Fail()
	}
}

func TestUpdateLambda(t *testing.T) {
	tk := new(ThresholdPublicKey)
	lambda := b(11)
	share1 := &PartialDecryption{3, b(5)}
	share2 := &PartialDecryption{7, b(3)}
	res := tk.updateLambda(share1, share2, lambda)
	if n(res) != 20 {
		t.Error("wrong lambda", n(res))
	}
}

func TestUpdateCprime(t *testing.T) {
	tk := new(ThresholdPublicKey)
	tk.N = b(99)
	cprime := b(77)
	lambda := b(52)
	share := &PartialDecryption{3, b(5)}
	cprime = tk.updateCprime(cprime, lambda, share)
	if n(cprime) != 8558 {
		t.Error("wrong cprime", cprime)
	}

}

func TestEncryptingDecryptingSimple(t *testing.T) {
	tkh, err := NewThresholdKeyGenerator(32, 2, 1, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	tpks, err := tkh.GenerateKeys()
	if err != nil {
		t.Error(err)
	}
	message := b(100)
	c := tpks[1].Encrypt(message)

	share1 := tpks[0].PartialDecrypt(c.C)
	message2, err := tpks[0].CombinePartialDecryptions([]*PartialDecryption{share1})
	if err != nil {
		t.Error(err)
	}
	if n(message) != n(message2) {
		t.Error("decrypted message is not the same one than the input one ", message2)
	}
}

func TestEncryptingDecrypting(t *testing.T) {
	tkh, err := NewThresholdKeyGenerator(32, 2, 2, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	tpks, err := tkh.GenerateKeys()
	if err != nil {
		t.Error(err)
	}
	message := b(100)
	c := tpks[1].Encrypt(message)

	share1 := tpks[0].PartialDecrypt(c.C)
	share2 := tpks[1].PartialDecrypt(c.C)
	message2, err := tpks[0].CombinePartialDecryptions([]*PartialDecryption{share1, share2})
	if err != nil {
		t.Error(err)
	}
	if n(message) != n(message2) {
		t.Error("The decrypted ciphered is not original massage but ", message2)
	}
}

func TestHomomorphicThresholdEncryption(t *testing.T) {
	tkh, err := NewThresholdKeyGenerator(32, 2, 2, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	tpks, _ := tkh.GenerateKeys()

	plainText1 := b(13)
	plainText2 := b(19)

	cipher1 := tpks[0].Encrypt(plainText1)
	cipher2 := tpks[1].Encrypt(plainText2)

	cipher3 := tpks[0].Add(cipher1, cipher2)

	share1 := tpks[0].PartialDecrypt(cipher3.C)
	share2 := tpks[1].PartialDecrypt(cipher3.C)

	combined, _ := tpks[0].CombinePartialDecryptions([]*PartialDecryption{share1, share2})

	expected := big.NewInt(32) // 13 + 19

	if !reflect.DeepEqual(combined, expected) { // 13 + 19
		t.Errorf("Unexpected decryption result. Expected %v but got %v", expected, combined)
	}
}

func TestDecryption(t *testing.T) {
	// test the correct decryption of '100'.
	share1 := &PartialDecryption{1, b(384111638639)}
	share2 := &PartialDecryption{2, b(235243761043)}
	tk := new(ThresholdPublicKey)
	tk.Threshold = 2
	tk.TotalNumberOfDecryptionServers = 2
	tk.N = b(637753)
	tk.VerificationKey = b(70661107826)
	if msg, err := tk.CombinePartialDecryptions([]*PartialDecryption{share1, share2}); err != nil {
		t.Error(err)
	} else if n(msg) != 100 {
		t.Error("decrypted message was not 100 but ", msg)
	}
}

func TestVerifyPartialDecryption(t *testing.T) {
	pk := getThresholdPrivateKey()
	if err := pk.VerifyPartialDecryption(); err != nil {
		t.Error(err)
	}
	pk.ID++
	if err := pk.VerifyPartialDecryption(); err == nil {
		t.Fail()
	}
}

func TestCombinePartialDecryptionsZKP(t *testing.T) {
	tkh, err := NewThresholdKeyGenerator(32, 2, 2, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	tpks, err := tkh.GenerateKeys()
	if err != nil {
		t.Error(err)
	}
	message := b(100)
	c := tpks[1].Encrypt(message)

	share1, err := tpks[0].PartialDecryptionWithZKP(c.C)
	if err != nil {
		t.Error(err)
	}
	share2, err := tpks[1].PartialDecryptionWithZKP(c.C)
	if err != nil {
		t.Error(err)
	}
	message2, err := tpks[0].CombinePartialDecryptionsZKP([]*PartialDecryptionZKP{share1, share2})
	if err != nil {
		t.Error(err)
	}
	if n(message) != n(message2) {
		t.Error("The decrypted ciphered is not original massage but ", message2)
	}
	share1.E = b(687687678)
	_, err = tpks[0].CombinePartialDecryptionsZKP([]*PartialDecryptionZKP{share1, share2})
	if err == nil {
		t.Fail()
	}
}

func TestCombinePartialDecryptionsWith100Shares(t *testing.T) {
	tkh, err := NewThresholdKeyGenerator(32, 100, 50, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	tpks, err := tkh.GenerateKeys()
	if err != nil {
		t.Error(err)
		return
	}
	message := b(100)
	c := tpks[1].Encrypt(message)

	shares := make([]*PartialDecryption, 75)
	for i := 0; i < 75; i++ {
		shares[i] = tpks[i].PartialDecrypt(c.C)
	}

	message2, err := tpks[0].CombinePartialDecryptions(shares)
	if err != nil {
		t.Error(err)
	}
	if n(message) != n(message2) {
		t.Error("The decrypted ciphered is not original massage but ", message2)
	}
}

func TestVerifyDecryption(t *testing.T) {
	tkh, err := NewThresholdKeyGenerator(32, 2, 2, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	tpks, err := tkh.GenerateKeys()

	pk := &tpks[0].ThresholdPublicKey
	if err != nil {
		t.Error(err)
	}
	expt := b(101)
	cipher := tpks[0].Encrypt(expt)

	pd1, err := tpks[0].PartialDecryptionWithZKP(cipher.C)
	if err != nil {
		t.Error(err)
	}
	pd2, err := tpks[1].PartialDecryptionWithZKP(cipher.C)
	if err != nil {
		t.Error(err)
	}
	pds := []*PartialDecryptionZKP{pd1, pd2}
	if err != nil {
		t.Error(err)
	}

	if err = pk.VerifyDecryption(cipher.C, b(101), pds); err != nil {
		t.Error(err)
	}
	if err = pk.VerifyDecryption(cipher.C, b(100), pds); err == nil {
		t.Error(err)
	}
	if err = pk.VerifyDecryption(new(big.Int).Add(b(1), cipher.C), b(101), pds); err == nil {
		t.Error(err)
	}
}

func BenchmarkThresholdDecrypt(b *testing.B) {
	tkh, err := NewThresholdKeyGenerator(512, 5, 5, rand.Reader)
	if err != nil {
		b.Error(err)
	}
	tpks, err := tkh.GenerateKeys()
	if err != nil {
		b.Fatal(err)
	}

	m := big.NewInt(100)
	c := tpks[1].Encrypt(m)
	for i := 0; i < b.N; i++ {
		ThresholdDecrypt(c, tpks)
	}
}

func ThresholdDecrypt(c *Ciphertext, tpks []*ThresholdSecretKey) (*big.Int, error) {
	share1 := tpks[0].PartialDecrypt(c.C)
	share2 := tpks[1].PartialDecrypt(c.C)
	share3 := tpks[2].PartialDecrypt(c.C)
	share4 := tpks[3].PartialDecrypt(c.C)
	share5 := tpks[4].PartialDecrypt(c.C)

	m, err := tpks[0].CombinePartialDecryptions(
		[]*PartialDecryption{share1, share2, share3, share4, share5})
	if err != nil {
		return nil, err
	}

	return m, nil
}
