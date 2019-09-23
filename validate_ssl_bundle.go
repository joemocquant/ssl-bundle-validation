package sslbundle

import "time"

type sslBundleError struct {
	chainsWithNoRoot map[int]bool
	expiredChains    map[int]bool
}

// ValidateSSLBundle validate a PEM encoded bundle against
// a PEM encoded private key and a hostname
func ValidateSSLBundle(bundle []byte, hostname string, privateKey []byte) *certChains {

	parsedBundle := parseSSLBundle(bundle)
	cc := buildCertificateChains(parsedBundle, hostname, privateKey)

	cc.bundleError = &sslBundleError{
		chainsWithNoRoot: make(map[int]bool),
		expiredChains:    make(map[int]bool),
	}
	cc.pathsValidation()
	return cc
}

// pathsValidation flags chains according to specific criteria.
func (cc *certChains) pathsValidation() {
	cc.flagChainsWithNoRoot()
	cc.flagExpiredChains()

	// Possible validators to build:
	// OCST: https://tools.ietf.org/html/rfc6960
	// CRL: https://tools.ietf.org/html/rfc5280
	// path length constraints
	// name constraints
	// policy constraints
}

// flagChainsWithNoRoot flags chains not ending
// with a root certificate.
func (cc *certChains) flagChainsWithNoRoot() {
	for i, chain := range cc.chains {
		if !cc.roots[chain[len(chain)-1]] {
			cc.bundleError.chainsWithNoRoot[i] = true
		}
	}
}

// flagExpiredChains flags chains with expired
// certificate(s).
func (cc *certChains) flagExpiredChains() {

	now := time.Now()

	for i, chain := range cc.chains {

		for _, k := range chain {
			cert := cc.pb.certs.certs[k]
			if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
				cc.bundleError.expiredChains[i] = true
				break
			}
		}
	}
}
