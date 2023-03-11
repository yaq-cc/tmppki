package tmppki

import "testing"

func testGenerateCertificateX(t *testing.T, alg Algorithm, str *SecurityStrength) {
	key, err := alg.GenerateKey(str)
	if err != nil {
		t.Fatal(err)
	}
	cert := key.Certificate(nil)
	DER, err := cert.MarshalPEM()
	if err != nil {
		t.Fatal(err)
	}
	t.Log(string(DER))	
}

func TestGenerateCertificateEd25519(t *testing.T) {
	testGenerateCertificateX(t, Ed25519, nil)
}

func TestGenerateCertificateECDSA(t *testing.T) {
	testGenerateCertificateX(t, ECDSA, S128)
}