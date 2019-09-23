package sslbundle

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"sort"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

type certData struct {
	cert    *x509.Certificate
	certDER []byte
	pk      *rsa.PrivateKey
}

type bundleData struct {
	bundle []byte
	certs  map[int]*certData
}

func buildBundle(t *testing.T) *bundleData {
	certs := buildChains(t)

	keys := []int{}
	for k := range certs {
		keys = append(keys, k)
	}
	sort.Ints(keys)

	bundle := []byte{}

	for _, k := range keys {
		pemCert := &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: certs[k].certDER,
		}
		certByte := pem.EncodeToMemory(pemCert)
		bundle = append(bundle, certByte...)
	}

	return &bundleData{bundle, certs}
}

// buildChains return a map of certificates,
// Those are vitually chained this way:
// Root 0 <- 1 <- 2 Leaf (with hostname "example1.com")
// Root 0 <- 1 <- 3 Leaf (with hostname "example2.com")
// Root 4 Leaf (with hostname "example2.com")
// Leaves: 2, 3, 4
// Roots: 0, 4
func buildChains(t *testing.T) map[int]*certData {
	certs := make(map[int]*certData)

	template := &x509.Certificate{
		IsCA:                  true,
		BasicConstraintsValid: true,
		SerialNumber:          big.NewInt(1234),
		NotAfter:              time.Now().AddDate(1, 0, 0),
	}

	cd0 := generateRootCertificateWithTemplate(t, template)
	certs[0] = cd0

	template = &x509.Certificate{
		IsCA:                  true,
		BasicConstraintsValid: true,
		SerialNumber:          big.NewInt(12345),
		NotAfter:              time.Now().AddDate(1, 0, 0),
	}

	cd1 := generateCertificateWithTemplateFromParent(t, template, cd0.cert, cd0.pk)
	certs[1] = cd1

	template = &x509.Certificate{
		SerialNumber: big.NewInt(12345),
		DNSNames:     []string{"example1.com"},
		NotAfter:     time.Now().AddDate(1, 0, 0),
	}

	cd2 := generateCertificateWithTemplateFromParent(t, template, cd1.cert, cd1.pk)
	certs[2] = cd2

	template = &x509.Certificate{
		SerialNumber: big.NewInt(12345),
		DNSNames:     []string{"example2.com"},
		NotAfter:     time.Now().AddDate(1, 0, 0),
	}

	cd3 := generateCertificateWithTemplateFromParent(t, template, cd1.cert, cd1.pk)
	certs[3] = cd3

	template = &x509.Certificate{
		IsCA:                  true,
		BasicConstraintsValid: true,
		SerialNumber:          big.NewInt(1234),
		DNSNames:              []string{"example2.com"},
		NotAfter:              time.Now().AddDate(1, 0, 0),
	}

	cd4 := generateRootCertificateWithTemplate(t, template)
	certs[4] = cd4
	return certs
}

func generateRootCertificateWithTemplate(t *testing.T, template *x509.Certificate) *certData {

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.Equal(t, err, nil)
	publicKey := &privateKey.PublicKey

	parent := template
	certDER, err := x509.CreateCertificate(rand.Reader, template, parent, publicKey, privateKey)
	assert.Equal(t, err, nil)

	cert, err := x509.ParseCertificate(certDER)
	assert.Equal(t, err, nil)

	return &certData{cert, certDER, privateKey}
}

func generateRootCertificateWithTemplateAndKey(t *testing.T, template *x509.Certificate, pk *rsa.PrivateKey) *certData {

	publicKey := &pk.PublicKey

	parent := template
	certDER, err := x509.CreateCertificate(rand.Reader, template, parent, publicKey, pk)
	assert.Equal(t, err, nil)

	cert, err := x509.ParseCertificate(certDER)
	assert.Equal(t, err, nil)

	return &certData{cert, certDER, pk}
}

func generateCertificateWithTemplateFromParent(
	t *testing.T,
	template *x509.Certificate,
	parent *x509.Certificate,
	parentPk *rsa.PrivateKey,
) *certData {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.Equal(t, err, nil)
	publicKey := &privateKey.PublicKey

	certDER, err := x509.CreateCertificate(rand.Reader, template, parent, publicKey, parentPk)
	assert.Equal(t, err, nil)

	cert, err := x509.ParseCertificate(certDER)
	assert.Equal(t, err, nil)

	return &certData{cert, certDER, privateKey}
}
