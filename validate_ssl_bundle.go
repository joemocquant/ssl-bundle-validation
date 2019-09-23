package sslbundle

import "time"

// FlaggedChains contains the flagged chains.
type FlaggedChains struct {
	ChainsWithNoRoot map[int]bool
	ExpiredChains    map[int]bool
}

// ValidateSSLBundle validate a PEM encoded bundle against
// a PEM encoded private key and a hostname.
func ValidateSSLBundle(bundle []byte, hostname string, privateKey []byte) *CertChains {

	parsedBundle := parseSSLBundle(bundle)
	cc := buildCertificateChains(parsedBundle, hostname, privateKey)

	cc.Fc = &FlaggedChains{
		ChainsWithNoRoot: make(map[int]bool),
		ExpiredChains:    make(map[int]bool),
	}
	cc.pathsValidation()
	return cc
}

// pathsValidation flags chains according to specific criteria.
func (cc *CertChains) pathsValidation() {
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
func (cc *CertChains) flagChainsWithNoRoot() {
	for i, chain := range cc.Chains {
		if !cc.roots[chain[len(chain)-1]] {
			cc.Fc.ChainsWithNoRoot[i] = true
		}
	}
}

// flagExpiredChains flags chains with expired
// certificate(s).
func (cc *CertChains) flagExpiredChains() {

	now := time.Now()

	for i, chain := range cc.Chains {

		for _, k := range chain {
			cert := cc.Pb.certs.certs[k]
			if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
				cc.Fc.ExpiredChains[i] = true
				break
			}
		}
	}
}
