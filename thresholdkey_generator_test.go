package paillier

import (
	"crypto/rand"
	"errors"
	"reflect"
	"testing"

	gmp "github.com/ncw/gmp"
)

var MockGenerateSafePrimes = func() (*gmp.Int, *gmp.Int, error) {
	return gmp.NewInt(887), gmp.NewInt(443), nil
}

func TestCreateThresholdKeyGenerator(t *testing.T) {
	var tests = map[string]struct {
		publicKeyBitLength             int
		totalNumberOfDecryptionServers int
		threshold                      int
		expectedError                  error
	}{
		"generator successfully created for 20 bit key length": {
			publicKeyBitLength:             20,
			totalNumberOfDecryptionServers: 6,
			threshold:                      5,
		},
		"generator can't be created for 19 bit key length": {
			publicKeyBitLength:             19,
			totalNumberOfDecryptionServers: 4,
			threshold:                      3,
			expectedError:                  errors.New("Public key bit length must be an even number"),
		},
		"generator successfully created for 18 bit key length": {
			publicKeyBitLength:             18,
			totalNumberOfDecryptionServers: 4,
			threshold:                      3,
		},
		"generator can't be created for 17 bit key length": {
			publicKeyBitLength:             17,
			totalNumberOfDecryptionServers: 4,
			threshold:                      3,
			expectedError:                  errors.New("Public key bit length must be an even number"),
		},
		"generator can't be created for 16 bit key length": {
			publicKeyBitLength:             16,
			totalNumberOfDecryptionServers: 4,
			threshold:                      3,
			expectedError:                  errors.New("Public key bit length must be at least 18 bits"),
		},
	}

	for testName, test := range tests {
		t.Run(testName, func(t *testing.T) {
			gen, err := NewThresholdKeyGenerator(
				test.publicKeyBitLength,
				test.totalNumberOfDecryptionServers,
				test.threshold,
				rand.Reader,
			)

			if !reflect.DeepEqual(test.expectedError, err) {
				t.Fatalf(
					"Unexpected error\nActual: %v\nExpected: %v",
					err,
					test.expectedError,
				)
			}

			if test.expectedError == nil {
				if gen == nil {
					t.Fatal(
						"Got nil generator, it should be successfully created",
					)
				}

				if test.publicKeyBitLength != gen.PublicKeyBitLength {
					t.Fatalf(
						"Unexpected public key length\nExpected: %v\nActual: %v",
						test.publicKeyBitLength,
						gen.PublicKeyBitLength,
					)
				}

				if test.threshold != gen.Threshold {
					t.Fatalf(
						"Unexpected threshold\nExpected: %v\nActual: %v",
						test.threshold,
						gen.Threshold,
					)
				}

				if test.totalNumberOfDecryptionServers != gen.TotalNumberOfDecryptionServers {
					t.Fatalf(
						"Unexpected number of decryption servers\nExpected: %v\nActual: %v",
						test.totalNumberOfDecryptionServers,
						gen.TotalNumberOfDecryptionServers,
					)
				}
			}
		})
	}
}

func TestGenerateNumbersOfCorrectBitLength(t *testing.T) {
	var tests = map[string]struct {
		publicKeyLength     int
		expectedPrimeLength int
	}{
		"public key bit length = 32, prime bit length = 16": {
			publicKeyLength:     32,
			expectedPrimeLength: 16,
		},
		"public key bit length = 64, prime bit length = 32": {
			publicKeyLength:     64,
			expectedPrimeLength: 32,
		},
	}

	for testName, test := range tests {
		t.Run(testName, func(t *testing.T) {
			gen, err := NewThresholdKeyGenerator(test.publicKeyLength, 10, 6, rand.Reader)
			if err != nil {
				t.Fatal(err)
			}

			err = gen.initNumerialValues()
			if err != nil {
				t.Fatal(err)
			}

			if gen.p.BitLen() != test.expectedPrimeLength {
				t.Fatalf(
					"Unexpected prime bit length\nExpected %v\n Actual %v",
					test.expectedPrimeLength,
					gen.p.BitLen(),
				)
			}

			if gen.q.BitLen() != test.expectedPrimeLength {
				t.Fatalf(
					"Unexpected prime bit length\nExpected %v\n Actual %v",
					test.expectedPrimeLength,
					gen.q.BitLen(),
				)
			}

			if gen.n.BitLen() != test.publicKeyLength {
				t.Fatalf(
					"Unexpected modulus bit length\nExpected %v\n Actual %v",
					test.publicKeyLength,
					gen.n.BitLen(),
				)
			}

			if new(gmp.Int).Mul(gen.p, gen.q).Cmp(gen.n) != 0 {
				t.Fatal("n != pq")
			}
		})
	}
}

func TestInitPandP1(t *testing.T) {
	tkh, err := NewThresholdKeyGenerator(32, 4, 3, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	tkh.initPandP1()
	IsSafePrime(ToBigInt(tkh.p), ToBigInt(tkh.p1), 16, t)
}

func TestInitQandQ1(t *testing.T) {
	tkh, err := NewThresholdKeyGenerator(32, 4, 3, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	tkh.initQandQ1()
	IsSafePrime(ToBigInt(tkh.q), ToBigInt(tkh.q1), 16, t)
}

func TestInitPsAndQs(t *testing.T) {
	tkh, err := NewThresholdKeyGenerator(32, 4, 3, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	tkh.initPsAndQs()

	IsSafePrime(ToBigInt(tkh.p), ToBigInt(tkh.p1), 16, t)
	IsSafePrime(ToBigInt(tkh.q), ToBigInt(tkh.q1), 16, t)
}

func TestArePsAndQsGood(t *testing.T) {
	tkh := new(ThresholdKeyGenerator)
	tkh.p, tkh.p1, tkh.q, tkh.q1 = b(887), b(443), b(839), b(419)
	if !tkh.arePsAndQsGood() {
		t.Fail()
	}

	tkh.p, tkh.p1, tkh.q, tkh.q1 = b(887), b(443), b(887), b(443)
	if tkh.arePsAndQsGood() {
		t.Fail()
	}

	tkh.p, tkh.p1, tkh.q, tkh.q1 = b(887), b(443), b(443), b(221)
	if tkh.arePsAndQsGood() {
		t.Fail()
	}
}

func TestInitShortcuts(t *testing.T) {
	tkh := new(ThresholdKeyGenerator)
	tkh.p, tkh.p1, tkh.q, tkh.q1 = b(839), b(419), b(887), b(443)
	tkh.initShortcuts()

	if !reflect.DeepEqual(ToBigInt(tkh.n), ToBigInt(b(744193))) {
		t.Error("wrong n", tkh.n)
	}
	if !reflect.DeepEqual(ToBigInt(tkh.m), ToBigInt(b(185617))) {
		t.Error("wrong m", tkh.m)
	}
	if !reflect.DeepEqual(ToBigInt(tkh.nm), ToBigInt(new(gmp.Int).Mul(b(744193), b(185617)))) {
		t.Error("wrong nm", tkh.nm)
	}
	if !reflect.DeepEqual(ToBigInt(tkh.nSquare), ToBigInt(new(gmp.Int).Mul(b(744193), b(744193)))) {
		t.Error("wrong nSquare", tkh.nSquare)
	}
}

func TestInitD(t *testing.T) {
	tkh := new(ThresholdKeyGenerator)
	tkh.p, tkh.p1, tkh.q, tkh.q1 = b(863), b(431), b(839), b(419)
	tkh.initShortcuts()
	tkh.initD()
	if n(tkh.d)%n(tkh.m) != 0 {
		t.Fail()
	}
	if n(tkh.d)%n(tkh.n) != 1 {
		t.Fail()
	}
}

func TestInitNumerialValues(t *testing.T) {
	tkh, err := NewThresholdKeyGenerator(32, 4, 3, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	if err := tkh.initNumerialValues(); err != nil {
		t.Error(err)
	}
}

func TestGenerateHidingPolynomial(t *testing.T) {
	tkh, err := NewThresholdKeyGenerator(32, 15, 10, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	if err := tkh.initNumerialValues(); err != nil {
		t.Error(err)
	}
	if err := tkh.generateHidingPolynomial(); err != nil {
		t.Error(err)
	}
	p := tkh.polynomialCoefficients
	if len(p) != tkh.Threshold {
		t.Fail()
	}
	if n(p[0]) != n(tkh.d) {
		t.Fail()
	}
	for i := 1; i < len(p); i++ {
		if j := n(p[i]); j < 0 || j >= n(tkh.nm) {
			t.Fail()
		}
	}
}

func TestComputeShare(t *testing.T) {
	tkh, err := NewThresholdKeyGenerator(32, 5, 3, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	tkh.nm = b(103)
	tkh.polynomialCoefficients = []*gmp.Int{b(29), b(88), b(51)}
	share := tkh.computeShare(2)
	if n(share) != 31 {
		t.Error("error computing a share.  ", share)
	}
}

func TestCreateShares(t *testing.T) {
	tkh, err := NewThresholdKeyGenerator(32, 100, 10, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	if err := tkh.initNumerialValues(); err != nil {
		t.Error(err)
	}
	if err := tkh.generateHidingPolynomial(); err != nil {
		t.Error(err)
	}

	if shares := tkh.createShares(); len(shares) != 100 {
		t.Fail()
	}
}

func TestCreateVerificationKeys(t *testing.T) {
	tkh := new(ThresholdKeyGenerator)
	tkh.TotalNumberOfDecryptionServers = 10
	tkh.v = b(54)
	tkh.nSquare = b(101 * 101)
	vArr := tkh.createVerificationKeys([]*gmp.Int{b(12), b(90), b(103)})
	exp := []*gmp.Int{b(6162), b(304), b(2728)}
	if !reflect.DeepEqual(vArr, exp) {
		t.Fail()
	}
}

func TestGetThresholdKeyGenerator(t *testing.T) {
	tkh, err := NewThresholdKeyGenerator(50, 10, 6, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	if err := tkh.initNumerialValues(); err != nil {
		t.Error(nil)
	}
}

func TestGenerate(t *testing.T) {
	tkh, err := NewThresholdKeyGenerator(32, 10, 6, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	tpks, err := tkh.GenerateKeys()
	if err != nil {
		t.Error(err)
		return
	}
	if len(tpks) != 10 {
		t.Fail()
	}
	for i, tpk := range tpks {
		if tpk.ID != i+1 {
			t.Fail()
		}
		if len(tpk.VerificationKeys) != 10 {
			t.Fail()
		}
		if tpk.N == nil {
			t.Fail()
		}
		if tpk.Threshold != 6 || tpk.TotalNumberOfDecryptionServers != 10 {
			t.Fail()
		}
	}
}

func TestComputeV(t *testing.T) {
	tkh, err := NewThresholdKeyGenerator(32, 10, 6, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	tkh.n = b(1907 * 1823)
	tkh.nSquare = new(gmp.Int).Mul(tkh.n, tkh.n)
	for i := 0; i < 100; i++ {
		if err := tkh.computeV(); err != nil {
			t.Error(err)
		}
		if tkh.v.Cmp(tkh.nSquare) > 0 {
			t.Error("v is too big")
		}
		if tkh.v.Cmp(tkh.n) > 0 {
			return
		}
	}
	t.Error(`v has never been bigger than n.  It is suspicious in the sense<
	than it was taken in the range 0...n**2 -1
	`)
}
