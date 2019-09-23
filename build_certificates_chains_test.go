package sslbundle

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBuildCertificateChains(t *testing.T) {

	bd := buildBundle(t)
	pb := parseSSLBundle(bd.bundle)

	t.Run("Build certificate chain for Leaf 2", func(t *testing.T) {

		pemPK := pem.EncodeToMemory(
			&pem.Block{
				Type:  "RSA PRIVATE KEY",
				Bytes: x509.MarshalPKCS1PrivateKey(bd.certs[2].pk),
			},
		)
		cc := buildCertificateChains(pb, "example1.com", pemPK)
		assert.Equal(t, pb, cc.pb)
		assert.Equal(t, 1, len(cc.chains))
		assert.Equal(t, true, reflect.DeepEqual([]int{2, 1, 0}, cc.chains[0]))
		assert.Equal(t, false, cc.hasNoLeaf || cc.hasNoRoot)
		assert.Equal(t, true, reflect.DeepEqual(map[int]bool{0: true, 4: true}, cc.roots))
		assert.Equal(t, true, reflect.DeepEqual([]int{2}, cc.leaves))
	})

	t.Run("Build certificate chain for Leaf 4", func(t *testing.T) {

		pemPK := pem.EncodeToMemory(
			&pem.Block{
				Type:  "RSA PRIVATE KEY",
				Bytes: x509.MarshalPKCS1PrivateKey(bd.certs[4].pk),
			},
		)
		cc := buildCertificateChains(pb, "example2.com", pemPK)
		assert.Equal(t, pb, cc.pb)
		assert.Equal(t, 1, len(cc.chains))
		assert.Equal(t, true, reflect.DeepEqual([]int{4}, cc.chains[0]))
		assert.Equal(t, false, cc.hasNoLeaf || cc.hasNoRoot)
		assert.Equal(t, true, reflect.DeepEqual(map[int]bool{0: true, 4: true}, cc.roots))
		assert.Equal(t, true, reflect.DeepEqual([]int{4}, cc.leaves))
	})
}

func TestBuildChainsFrom(t *testing.T) {
	t.Run("Build nodes for a list of certificates", func(t *testing.T) {

		certs := buildChains(t)
		x509certs := make(map[int]*x509.Certificate)
		for i, cd := range certs {
			x509certs[i] = cd.cert
		}
		nodes := buildNodes(x509certs)

		// Arbitrary choosing leaves
		leaves := []int{0, 2, 3, 4}
		chains := buildChainsFrom(-1, leaves, nodes)
		assert.Equal(t, 4, len(chains))

		want := [][]int{[]int{0}, []int{4}, []int{2, 1, 0}, []int{3, 1, 0}}
		checked := make(map[int]bool)
		checkedCount := 0
		for _, chain := range chains {
			for j, c := range want {
				if !checked[j] && reflect.DeepEqual(chain, c) {
					checked[j] = true
					checkedCount++
					break
				}
			}
		}
		assert.Equal(t, checkedCount, len(want))
	})
}

func TestBuildNodes(t *testing.T) {

	t.Run("Build nodes for a list of certificates", func(t *testing.T) {

		certs := buildChains(t)
		x509certs := make(map[int]*x509.Certificate)
		for i, cd := range certs {
			x509certs[i] = cd.cert
		}
		nodes := buildNodes(x509certs)

		assert.Equal(t, 0, len(nodes[0].parents))
		assert.Equal(t, true, reflect.DeepEqual(nodes[1].parents, []int{0}))
		assert.Equal(t, true, reflect.DeepEqual(nodes[2].parents, []int{1}))
		assert.Equal(t, true, reflect.DeepEqual(nodes[3].parents, []int{1}))
		assert.Equal(t, 0, len(nodes[4].parents))
	})
}

func TestFindLeaves(t *testing.T) {
	certs := make(map[int]*x509.Certificate)
	pemCerts := make(map[int]*pem.Block)

	// Cert is a leaf
	hostname := "example.com"
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1234),
		DNSNames:     []string{hostname},
	}

	cd := generateRootCertificateWithTemplate(t, template)

	pemCert := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cd.certDER,
	}

	pemPK := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(cd.pk),
		},
	)
	certs[0] = cd.cert
	pemCerts[0] = pemCert

	// Cert is not a leaf (no matching DNSName)
	template = &x509.Certificate{
		SerialNumber: big.NewInt(1234),
		DNSNames:     []string{"example.com1"},
	}

	cd = generateRootCertificateWithTemplateAndKey(t, template, cd.pk)
	pemCert = &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cd.certDER,
	}

	certs[1] = cd.cert
	pemCerts[1] = pemCert

	keys := findLeaves(certs, hostname, pemPK, pemCerts)
	assert.Equal(t, true, reflect.DeepEqual(keys, []int{0}))
}
func TestIsLeaf(t *testing.T) {

	testCases := []struct {
		desc     string
		isLeaf   bool
		hostname string
		template *x509.Certificate
	}{
		{
			desc:     "Cert is leaf",
			isLeaf:   true,
			hostname: "example.com",
			template: &x509.Certificate{
				SerialNumber: big.NewInt(1234),
				DNSNames:     []string{"example.com"},
			},
		},
		{
			desc:     "Cert is not a leaf (name does not match)",
			isLeaf:   false,
			hostname: "example.com",
			template: &x509.Certificate{
				SerialNumber: big.NewInt(1234),
				DNSNames:     []string{"example.com2"},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {

			cd := generateRootCertificateWithTemplate(t, tc.template)

			pemCert := &pem.Block{
				Type:  "CERTIFICATE",
				Bytes: cd.certDER,
			}

			pemPK := pem.EncodeToMemory(
				&pem.Block{
					Type:  "RSA PRIVATE KEY",
					Bytes: x509.MarshalPKCS1PrivateKey(cd.pk),
				},
			)

			assert.Equal(t, tc.isLeaf, isLeaf(cd.cert, tc.hostname, pemPK, pemCert))
		})
	}

	t.Run("Cert is not leaf (no matching keys)", func(t *testing.T) {

		hostname := "example.com"
		template := &x509.Certificate{
			SerialNumber: big.NewInt(1234),
			DNSNames:     []string{hostname},
		}

		cd := generateRootCertificateWithTemplate(t, template)

		pemCert := &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cd.certDER,
		}

		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		assert.Equal(t, err, nil)

		pemPK := pem.EncodeToMemory(
			&pem.Block{
				Type:  "RSA PRIVATE KEY",
				Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
			},
		)
		assert.Equal(t, false, isLeaf(cd.cert, hostname, pemPK, pemCert))
	})
}

func TestFindRoots(t *testing.T) {

	certs := make(map[int]*x509.Certificate)

	// Cert is not root (not self-signed)
	templateParent := &x509.Certificate{
		SerialNumber: big.NewInt(1234),
	}

	template := &x509.Certificate{
		IsCA:                  true,
		BasicConstraintsValid: true,
		SerialNumber:          big.NewInt(1234),
	}

	parentKey, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.Equal(t, err, nil)
	cert := generateCertificateWithTemplateFromParent(t, template, templateParent, parentKey)
	certs[0] = cert.cert

	// Cert is not root (Issuer and Subject not matching)
	templateParent = &x509.Certificate{
		SerialNumber: big.NewInt(1234),
	}

	template = &x509.Certificate{
		IsCA:                  true,
		BasicConstraintsValid: true,
		SerialNumber:          big.NewInt(1234),
	}

	parentKey, err = rsa.GenerateKey(rand.Reader, 2048)
	assert.Equal(t, err, nil)
	cert = generateCertificateWithTemplateFromParent(t, template, templateParent, parentKey)
	certs[1] = cert.cert

	// Cert is root
	template = &x509.Certificate{
		IsCA:                  true,
		BasicConstraintsValid: true,
		SerialNumber:          big.NewInt(1234),
	}
	cd := generateRootCertificateWithTemplate(t, template)
	certs[2] = cd.cert

	keys := findRoots(certs)
	assert.Equal(t, true, reflect.DeepEqual(keys, map[int]bool{2: true}))
}

func TestIsRoot(t *testing.T) {

	testCases := []struct {
		desc     string
		isRoot   bool
		template *x509.Certificate
	}{
		{
			desc:   "Cert is root",
			isRoot: true,
			template: &x509.Certificate{
				IsCA:                  true,
				BasicConstraintsValid: true,
				SerialNumber:          big.NewInt(1234),
			},
		},
		{
			desc:   "Cert is not root: non-CA (BasicConstraints not validated)",
			isRoot: false,
			template: &x509.Certificate{
				IsCA:                  true,
				BasicConstraintsValid: false,
				SerialNumber:          big.NewInt(1234),
			},
		},
		{
			desc:   "Cert is not root: non-CA",
			isRoot: false,
			template: &x509.Certificate{
				IsCA:                  false,
				BasicConstraintsValid: true,
				SerialNumber:          big.NewInt(1234),
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {

			cd := generateRootCertificateWithTemplate(t, tc.template)
			assert.Equal(t, tc.isRoot, isRoot(cd.cert))
		})
	}

	t.Run("Cert is not root (not self-signed)", func(t *testing.T) {

		templateParent := &x509.Certificate{
			SerialNumber: big.NewInt(1234),
		}

		template := &x509.Certificate{
			IsCA:                  true,
			BasicConstraintsValid: true,
			SerialNumber:          big.NewInt(1234),
		}

		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		assert.Equal(t, err, nil)
		cert := generateCertificateWithTemplateFromParent(t, template, templateParent, privateKey)
		assert.Equal(t, false, isRoot(cert.cert))
	})

	t.Run("Cert is not root (Issuer and Subject not matching)", func(t *testing.T) {

		parent := &x509.Certificate{
			SerialNumber: big.NewInt(1234),
			Subject: pkix.Name{
				Country:      []string{"Earth"},
				Organization: []string{"Org"},
			},
		}

		child := &x509.Certificate{
			IsCA:                  true,
			BasicConstraintsValid: true,
			SerialNumber:          big.NewInt(1234),
			Subject: pkix.Name{
				Country:      []string{"Earth"},
				Organization: []string{"Org2"},
			},
		}

		parentCert := generateRootCertificateWithTemplate(t, parent)
		childCertDER, err := x509.CreateCertificate(rand.Reader, child, parentCert.cert, &parentCert.pk.PublicKey, parentCert.pk)
		assert.Equal(t, err, nil)

		childCert, err := x509.ParseCertificate(childCertDER)
		assert.Equal(t, err, nil)
		assert.Equal(t, false, isRoot(childCert))
	})
}
