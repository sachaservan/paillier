package main

import (
	"fmt"
	"math/big"
	"paillier"
)

func b(i int) *big.Int {
	return big.NewInt(int64(i))
}

func n(i *big.Int) int {
	return int(i.Int64())
}

func main() {

	sk := paillier.CreateSecretKey(10)
	pk := sk.PublicKey

	plaintext1 := b(21)
	plaintext2 := b(5)

	fmt.Println("plaintext1: " + plaintext1.String())
	fmt.Println("plaintext2: " + plaintext2.String())

	ciphertext1 := pk.Encrypt(plaintext1)
	ciphertext2 := pk.Encrypt(plaintext2)

	fmt.Println("ciphertexttext1: " + ciphertext1.C.String())
	fmt.Println("ciphertextext2: " + ciphertext2.C.String())

	fmt.Println("plaintext1: " + sk.Decrypt(ciphertext1).String())
	fmt.Println("plaintext2: " + sk.Decrypt(ciphertext2).String())

	ciphertextsum := pk.EAdd(ciphertext1, ciphertext2)
	ciphertextmult := pk.ECMult(ciphertext1, b(3))

	plaintextresult := sk.Decrypt(ciphertextsum)
	plaintextresult2 := sk.Decrypt(ciphertextmult)

	fmt.Println(plaintext1.String() + " + " + plaintext2.String() + " = " + plaintextresult.String())
	fmt.Println(plaintext1.String() + " * 3 = " + plaintextresult2.String())

}
