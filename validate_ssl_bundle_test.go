package sslbundle

import (
	"crypto/x509"
	"encoding/pem"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidateSSLBundle(t *testing.T) {

	bd := buildBundle(t)

	pemPK := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(bd.certs[2].pk),
		},
	)

	cc := ValidateSSLBundle(bd.bundle, "example1.com", pemPK)
	assert.Equal(t, 1, len(cc.Chains))
	assert.Equal(t, true, reflect.DeepEqual(cc.Chains[0], []int{2, 1, 0}))
	assert.Equal(t, 0, len(cc.Fc.ChainsWithNoRoot))
	assert.Equal(t, 0, len(cc.Fc.ExpiredChains))
}
