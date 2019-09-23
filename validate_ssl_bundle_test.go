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
	assert.Equal(t, 1, len(cc.chains))
	assert.Equal(t, true, reflect.DeepEqual(cc.chains[0], []int{2, 1, 0}))
	assert.Equal(t, 0, len(cc.bundleError.chainsWithNoRoot))
	assert.Equal(t, 0, len(cc.bundleError.expiredChains))
}
