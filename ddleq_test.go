package paillier

import (
	"testing"

	gmp "github.com/ncw/gmp"
)

func TestDDLEQProofInstanceCompleteness(t *testing.T) {

	for i := 0; i < 100; i++ {
		sk, pk := KeyGen(128)

		ct := pk.NestedEncrypt(gmp.NewInt(int64(i * i)))
		ctr, a, b := pk.NestedRandomize(ct)

		proof, err := sk.proveDDLEQInstance(ct, ctr, a, b)
		if err != nil {
			t.Fatal(err)
		}

		ok := pk.verifyDDLEQProofInstance(ct, ctr, proof)

		if !ok {
			t.Error("DDLEQ proof is not complete")
		}
	}
}

func TestDDLEQProofCompleteness(t *testing.T) {

	secpar := 10

	for i := 0; i < 100; i++ {

		sk, pk := KeyGen(128)

		ct := pk.NestedEncrypt(gmp.NewInt(int64(i * i)))
		ctr, a, b := pk.NestedRandomize(ct)

		proof, err := sk.ProveDDLEQ(secpar, ct, ctr, a, b)
		if err != nil {
			t.Fatal(err)
		}

		ok := pk.VerifyDDLEQProof(ct, ctr, proof)

		if !ok {
			t.Error("DDLEQ proof is not complete")
		}
	}
}

func TestDDLEQProofSoundness(t *testing.T) {

	secpar := 10

	for i := 0; i < 100; i++ {
		sk, pk := KeyGen(128)

		ct := pk.NestedEncrypt(gmp.NewInt(int64(i * i)))
		ctr, r1, s1 := pk.NestedRandomize(ct)
		proof, _ := sk.ProveDDLEQ(secpar, ct, ctr, r1, s1)

		ctr = pk.EncryptAtLevel(gmp.NewInt(int64(i*i)), EncLevelTwo)
		ok := pk.VerifyDDLEQProof(ct, ctr, proof)

		if ok {
			t.Error("DDLEQ proof is not sound")
		}
	}
}

func BenchmarkProve(b *testing.B) {

	secpar := 40

	sk, pk := KeyGen(1024)
	ct := pk.NestedEncrypt(gmp.NewInt(0))
	ctr, r1, s1 := pk.NestedRandomize(ct)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		sk.ProveDDLEQ(secpar, ct, ctr, r1, s1)
	}
}

func BenchmarkVerify(b *testing.B) {

	secpar := 40

	sk, pk := KeyGen(1024)
	ct := pk.NestedEncrypt(gmp.NewInt(0))
	ctr, r1, s1 := pk.NestedRandomize(ct)
	proof, _ := sk.ProveDDLEQ(secpar, ct, ctr, r1, s1)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		pk.VerifyDDLEQProof(ct, ctr, proof)
	}
}
