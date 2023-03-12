package tmppki

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"time"
)

// Constants and Globals

func DefaultCertTemplate() *x509.Certificate {
	now := time.Now()
	cert := &x509.Certificate{
		SerialNumber: RandomBigInt(),
		Subject: pkix.Name{
			CommonName: "Temporary PKI Certificate",
		},
		NotBefore:    now,
		NotAfter:     now.AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	return cert
}

func DefaultCATemplate() *x509.Certificate {
	tmpl := DefaultCertTemplate()
	tmpl.Subject = pkix.Name{
		CommonName: "Temporary PKI Certificate Authority",
	}
	tmpl.IsCA = true
	tmpl.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign
	tmpl.BasicConstraintsValid = true
	return tmpl
}

var CertificatePEMHeader = "CERTIFICATE"

// Certificates

type Certificate struct {
	creator func(c *Certificate) error
	key     *Key
	der     []byte
	cert    *x509.Certificate
}

func (c Certificate) Key() *Key {
	return c.key
}

func (c Certificate) Private() PrivateKey {
	return c.key.priv
}

func (c Certificate) Public() PublicKey {
	return c.key.priv.Public()
}

func (c Certificate) Certificate() *x509.Certificate {
	return c.cert
}

func (c *Certificate) MarshalDER() ([]byte, error) {
	err := c.creator(c)
	if err != nil {
		return nil, err
	}
	return c.der, nil
}

func (c *Certificate) MarshalPEM() ([]byte, error) {
	if c.der == nil {
		_, err := c.MarshalDER()
		if err != nil {
			return nil, err
		}
	}

	block := &pem.Block{
		Type:  CertificatePEMHeader,
		Bytes: c.der,
	}
	PEM := pem.EncodeToMemory(block)
	return PEM, nil
}

func (c *Certificate) EncodePEM(w io.WriteCloser) error {
	defer w.Close()
	if c.der == nil {
		_, err := c.MarshalDER()
		if err != nil {
			return err
		}
	}

	block := &pem.Block{
		Type:  CertificatePEMHeader,
		Bytes: c.der,
	}
	return pem.Encode(w, block)

}

// Helpers

func RandomBigInt() *big.Int {
	//Max random value, a 130-bits integer, i.e 2^130 - 1
	max := new(big.Int)
	max.Exp(big.NewInt(2), big.NewInt(130), nil).Sub(max, big.NewInt(1))

	//Generate cryptographically strong pseudo-random between 0 - max
	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		panic(err)
	}
	return n
}
