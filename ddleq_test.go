package paillier

import (
	"testing"

	gmp "github.com/ncw/gmp"
)

func TestDDLEQProofCompleteness(t *testing.T) {

	for i := 0; i < 100; i++ {

		sk, pk := KeyGen(128)

		inner := pk.EncryptAtLevel(gmp.NewInt(int64(i*i)), EncLevelOne)
		ct := pk.EncryptAtLevel(inner.C, EncLevelTwo)
		ctr, a, b := pk.NestedRandomize(ct)

		proof, err := sk.ProveDDLEQ(ct, ctr, a, b)
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

	for i := 0; i < 100; i++ {
		sk, pk := KeyGen(128)

		inner := pk.AltEncryptAtLevel(gmp.NewInt(int64(i*i)), EncLevelOne)
		ct := pk.EncryptAtLevel(inner.C, EncLevelTwo)
		ctr, r1, s1 := pk.NestedRandomize(ct)
		proof, _ := sk.ProveDDLEQ(ct, ctr, r1, s1)

		ctr = pk.EncryptAtLevel(gmp.NewInt(int64(i*i)), EncLevelTwo)
		ok := pk.VerifyDDLEQProof(ct, ctr, proof)

		// since the protocol has soundness 1/2 we must make sure that the
		// verification fails only when b = 1
		chalBit := RandomOracleBit(ct.C, ctr.C, proof.X, proof.Y, proof.Alpha)

		if ok && chalBit {
			t.Error("DDLEQ proof is not sound")
		}
	}
}

func BenchmarkProve(b *testing.B) {
	sk, pk := KeyGen(1024)
	inner := pk.AltEncryptAtLevel(gmp.NewInt(int64(0)), EncLevelOne)
	ct := pk.EncryptAtLevel(inner.C, EncLevelTwo)
	ctr, r1, s1 := pk.NestedRandomize(ct)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		sk.ProveDDLEQ(ct, ctr, r1, s1)
	}
}

func BenchmarkVerify(b *testing.B) {
	sk, pk := KeyGen(1024)
	inner := pk.AltEncryptAtLevel(gmp.NewInt(int64(0)), EncLevelOne)
	ct := pk.EncryptAtLevel(inner.C, EncLevelTwo)
	ctr, r1, s1 := pk.NestedRandomize(ct)
	proof, _ := sk.ProveDDLEQ(ct, ctr, r1, s1)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		pk.VerifyDDLEQProof(ct, ctr, proof)
	}
}
