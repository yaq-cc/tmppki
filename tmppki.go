package tmppki

import (
	"crypto/x509"
	"net/http"
	"os"
	"strings"
)

type Path string

func (f Path) Dir() string {
	if string(f) == "" {
		return ""
	}
	parts := strings.Split(string(f), "/")
	count := len(parts)
	if count == 1 {
		return ""
	} else {
		return strings.Join(parts[:count-1], "/")
	}
}

func (f Path) Pattern() string {
	if string(f) == "" {
		return ""
	}

	parts := strings.Split(string(f), "/")
	count := len(parts)
	return parts[count-1]
}

type TemporaryPKI struct {
	key        *Key
	cert       *Certificate
	caKey      *Key
	caCert     *Certificate
	keyPath    Path
	certPath   Path
	caKeyPath  Path
	caCertPath Path
	ready      bool
}

func NewTemporaryPKI(alg Algorithm, str *SecurityStrength, tmpl *x509.Certificate) (*TemporaryPKI, error) {
	tmppki := &TemporaryPKI{}
	caKey, err := RSA.GenerateKey(S160)
	if err != nil {
		return nil, err
	}
	caTmpl := DefaultCATemplate()
	caCert := caKey.Certificate(caTmpl, nil, nil)
	key, err := alg.GenerateKey(str)
	if err != nil {
		return nil, err
	}

	tmppki.key = key
	tmppki.cert = key.Certificate(nil, caTmpl, caKey)
	tmppki.caKey = caKey
	tmppki.caCert = caCert
	tmppki.keyPath = "/tmp/server.key"
	tmppki.certPath = "/tmp/server.crt"
	tmppki.caKeyPath = "/tmp/tmppki-ca.key"
	tmppki.caCertPath = "/tmp/tmppki-ca.crt"
	tmppki.ready = false
	return tmppki, nil
}

func (t TemporaryPKI) KeyPath() string {
	return string(t.keyPath)
}

func (t TemporaryPKI) CertPath() string {
	return string(t.certPath)
}

func (t TemporaryPKI) CAKeyPath() string {
	return string(t.caKeyPath)
}

func (t TemporaryPKI) CACertPath() string {
	return string(t.caCertPath)
}

func (t *TemporaryPKI) GeneratePKI() (func() error, error) {
	tmpKeyfile, err := os.CreateTemp(t.keyPath.Dir(), t.keyPath.Pattern())
	if err != nil {
		return nil, err
	}
	t.keyPath = Path(tmpKeyfile.Name())
	err = t.key.EncodePEM(tmpKeyfile)
	if err != nil {
		return nil, err
	}

	tmpCertfile, err := os.CreateTemp(t.certPath.Dir(), t.certPath.Pattern())
	if err != nil {
		return nil, err
	}
	t.certPath = Path(tmpCertfile.Name())
	err = t.cert.EncodePEM(tmpCertfile)
	if err != nil {
		return nil, err
	}

	tmpCaCertfile, err := os.CreateTemp(t.caCertPath.Dir(), t.caCertPath.Pattern())
	if err != nil {
		return nil, err
	}
	t.caCertPath = Path(tmpCaCertfile.Name())
	err = t.cert.EncodePEM(tmpCaCertfile)
	if err != nil {
		return nil, err
	}

	remover := func() error {
		err := os.Remove(t.KeyPath())
		if err != nil {
			return err
		}
		err = os.Remove(t.CertPath())
		if err != nil {
			return err
		}
		err = os.Remove(t.CACertPath())
		if err != nil {
			return err
		}

		return nil
	}

	t.ready = true
	return remover, nil
}

func (t *TemporaryPKI) ListenAndServeTLS(s *http.Server) error {
	var remover func() error
	if !t.ready {
		r, err := t.GeneratePKI()
		if err != nil {
			return err
		}
		remover = r
	}
	certFile := t.CertPath()
	keyFile := t.KeyPath()
	defer remover()
	return s.ListenAndServeTLS(certFile, keyFile)
}
