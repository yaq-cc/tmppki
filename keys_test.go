package tmppki

import (
	"testing"
)

func testGenerateKey(t *testing.T, alg Algorithm, str *SS) {
	key, err := alg.GenerateKey(str)
	if err != nil {
		t.Fatal(err)
		t.Fail()
	}
	PEM, err := key.MarshalPEM()
	if err != nil {
		t.Fatal(err)
		t.Fail()
	}
	t.Log(string(PEM))
}

func TestGenerateECDSAKeys(t *testing.T) {
	for str := range EllipticStrengths {
		testGenerateKey(t, ECDSA, str)
	}
}

func TestGenerateEd25519Keys(t *testing.T) {
	testGenerateKey(t, Ed25519, nil)
}

func TestGenerateRSAKeys(t *testing.T) {
	for str := range RSAStrengths {
		t.Log(*str)
		testGenerateKey(t, RSA, str)
	}
}
