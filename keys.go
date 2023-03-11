package tmppki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
)

// Errors
var (
	ErrUnrecognizedAlgorithm = fmt.Errorf("unrecognized key algorithm")
	ErrStrengthNotAvailable  = fmt.Errorf("bit strength not available")
	ErrStrengthWasNil        = fmt.Errorf("strength must not be nil")
	ErrPublicKeysDontMatch   = fmt.Errorf("public keys don't match")
)

// Aliases
type PublicKey = crypto.PublicKey

// The true PrivateKey interface as per https://pkg.go.dev/crypto#PrivateKey
type PrivateKey interface {
	Public() PublicKey
	Equal(x crypto.PrivateKey) bool
}

// Algorithms
type Algorithm string

const (
	ECDSA   Algorithm = "ecdsa"
	Ed25519 Algorithm = "ed25519"
	RSA     Algorithm = "rsa"
)

var Algorithms = map[string]Algorithm{
	"ecdsa":   ECDSA,
	"ed25519": Ed25519,
	"rsa":     RSA,
}

var AlgorithmPEMHeaders = map[Algorithm]string{
	ECDSA:   "EC PRIVATE KEY",
	Ed25519: "OPENSSH PRIVATE KEY",
	RSA:     "RSA PRIVATE KEY",
}

func (a Algorithm) Header() string {
	return AlgorithmPEMHeaders[a]
}

func (a Algorithm) GenerateKey(str *SecurityStrength) (*Key, error) {
	rr := rand.Reader
	res := &Key{}
	switch a {
	case ECDSA:
		if str == nil {
			return nil, ErrStrengthWasNil
		}
		curve, ok := EllipticStrengths[str]
		if !ok {
			return nil, ErrStrengthNotAvailable
		}
		key, err := ecdsa.GenerateKey(curve, rr)
		if err != nil {
			return nil, err
		}
		res.alg = a
		res.priv = key
		return res, nil
	case Ed25519:
		pub, key, err := ed25519.GenerateKey(rr)
		if err != nil {
			return nil, err
		}
		if !pub.Equal(key.Public()) {
			return nil, ErrPublicKeysDontMatch
		}
		res.alg = a
		res.priv = key
		return res, nil
	case RSA:
		if str == nil {
			return nil, ErrStrengthWasNil
		}
		bits, ok := RSAStrengths[str]
		if !ok {
			return nil, ErrStrengthNotAvailable
		}
		key, err := rsa.GenerateKey(rr, bits)
		if err != nil {
			return nil, err
		}
		res.alg = a
		res.priv = key
		return res, nil
	default:
		return nil, ErrUnrecognizedAlgorithm
	}
}

func (a Algorithm) MustGenerateKey(str *SecurityStrength) *Key {
	key, err := a.GenerateKey(str)
	if err != nil {
		panic(err)
	}
	return key
}

// Security Strengths (bit strengths)
type SecurityStrength int
type SS = SecurityStrength

var (
	SS112 SS  = 112
	SS128 SS  = 128
	SS160 SS  = 160
	SS192 SS  = 192
	SS256 SS  = 256
	S112  *SS = &SS112
	S128  *SS = &SS128
	S160  *SS = &SS160
	S192  *SS = &SS192
	S256  *SS = &SS256
)

var (
	EllipticStrengths = map[*SecurityStrength]elliptic.Curve{
		S112: elliptic.P224(),
		S128: elliptic.P256(),
		S192: elliptic.P384(),
	}
	RSAStrengths = map[*SecurityStrength]int{
		S112: 2048,
		S128: 3072,
		S160: 4096,
		S192: 7680,
		S256: 15360,
	}
)

// Keys
type Key struct {
	alg  Algorithm
	priv PrivateKey
}

// func NewKey(alg Algorithm) *Key {
// 	return &Key{
// 		alg: alg,
// 	}
// }

func (k Key) Algorithm() Algorithm {
	return k.alg
}

func (k Key) Private() PrivateKey {
	return k.priv
}

func (k Key) Public() PublicKey {
	return k.priv.Public()
}

func (k Key) MarshalDER() ([]byte, error) {
	switch k.alg {
	case ECDSA:
		key := k.priv.(*ecdsa.PrivateKey)
		return x509.MarshalECPrivateKey(key)
	case Ed25519:
		key := k.priv.(ed25519.PrivateKey)
		return x509.MarshalPKCS8PrivateKey(key)
	case RSA:
		key := k.priv.(*rsa.PrivateKey)
		return x509.MarshalPKCS1PrivateKey(key), nil
	default:
		return nil, ErrUnrecognizedAlgorithm
	}
}

func (k Key) MarshalPEM() ([]byte, error) {
	DER, err := k.MarshalDER()
	if err != nil {
		return nil, err
	}
	block := &pem.Block{
		Type:  k.alg.Header(),
		Bytes: DER,
	}
	PEM := pem.EncodeToMemory(block)
	return PEM, nil

}

func (k Key) EncodePEM(w io.WriteCloser) error {
	defer w.Close()
	DER, err := k.MarshalDER()
	if err != nil {
		return err
	}
	block := &pem.Block{
		Type:  k.alg.Header(),
		Bytes: DER,
	}
	err = pem.Encode(w, block)
	if err != nil {
		return nil
	}
	return nil
}

func (k *Key) Certificate(tmpl *x509.Certificate) *Certificate {
	if tmpl == nil {
		tmpl = DefaultCertTemplate()
	}

	creator := func(cert *Certificate) error {
		DER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, k.Public(), k.Private())
		if err != nil {
			return err
		}
		cert.der = DER
		return nil
	}

	return &Certificate{
		creator: creator,
		key:     k,
	}
}
