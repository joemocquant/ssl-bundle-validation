package sslbundle

import (
	"crypto/x509"
	"encoding/pem"
	"sync"
)

type blockType string

const (
	// CERTIFICATE block type
	certificate blockType = "CERTIFICATE"
	// PUBLIC KEY block type
	publicKey blockType = "PUBLIC KEY"
)

// ParsedBundle contains the certificates and errors
// encoutered during bundle parsing.
type ParsedBundle struct {
	Be       *BundleError
	certs    *certificates
	pemCerts map[int]*pem.Block
}

// BundleError provides the errors recorded
// at PEM Block level and PEM encoded certificate level.
type BundleError struct {
	Berrs BlockErrors
	Cerrs *CertErrors
}

// BlockErrors is a map to handle PEM block errors.
type BlockErrors map[int]*BlockError

// BlockError provides the error for a PEM Block.
type BlockError struct {
	IsNotCertificate    bool
	BlockContainsHeader bool
}

// CertErrors is a concurrent map to handle certificate errors.
type CertErrors struct {
	*sync.Mutex
	Errs map[int]*CertError
}

// CertError provides the error for a PEM encoded certificate.
type CertError struct {
	ParseErr error
}

func (cerrs *CertErrors) addParseError(i int, err error) {
	cerrs.Lock()
	defer cerrs.Unlock()

	if cerrs.Errs == nil {
		cerrs.Errs = make(map[int]*CertError)
	}
	cerrs.Errs[i] = &CertError{ParseErr: err}
}

// certificates is a concurrent map to handle x509 certificates.
type certificates struct {
	*sync.Mutex
	certs map[int]*x509.Certificate
}

func (certs *certificates) addCertificate(i int, cert *x509.Certificate) {
	certs.Lock()
	defer certs.Unlock()

	if certs.certs == nil {
		certs.certs = make(map[int]*x509.Certificate)
	}
	certs.certs[i] = cert
}

// parseSSLBundle parses the SSL bundle provided and returns
// an array of matching x509 certificates. It also returns any
// errors encountered.
func parseSSLBundle(bundle []byte) *ParsedBundle {

	pemCerts, berrs := extractPEMCerts(bundle)
	certs, cerrs := parsePEMCertificates(pemCerts)

	return &ParsedBundle{&BundleError{berrs, cerrs}, certs, pemCerts}
}

// extractPEMCerts decodes the SSL bundle provided into an array of PEM
// Certs. It also returns any errors encountered during decoding.
func extractPEMCerts(bundle []byte) (map[int]*pem.Block, BlockErrors) {
	return extractPEMValues(bundle, []blockType{certificate})
}

// extractPEMValues decodes the SSL bundle provided into an array of PEM
// Values. PEM values to decode are passed as a parameter.
// It also returns any errors encountered during decoding.
func extractPEMValues(
	bundle []byte,
	allowedBlockTypes []blockType,
) (map[int]*pem.Block, BlockErrors) {

	pemValues := make(map[int]*pem.Block)
	berrs := make(BlockErrors)

	blockCount := -1

	isBlockAllowed := func(bt blockType, allowedBlockTypes []blockType) bool {
		for _, allowedBlockType := range allowedBlockTypes {
			if allowedBlockType == bt {
				return true
			}
		}
		return false
	}

	for len(bundle) > 0 {

		var block *pem.Block
		block, bundle = pem.Decode(bundle)
		if block == nil {
			break
		}
		blockCount++
		if !isBlockAllowed(blockType(block.Type), allowedBlockTypes) {
			berrs[blockCount] = &BlockError{true, false}
		}

		if len(block.Headers) != 0 {
			berrs[blockCount] = &BlockError{false, true}
		}

		if _, ok := berrs[blockCount]; ok {
			continue
		}

		pemValues[blockCount] = block
	}

	return pemValues, berrs
}

// parsePEMCertificates parses the PEM certificates provided
// concurrently. It also returns any errors encountered during parsing.
func parsePEMCertificates(pemCerts map[int]*pem.Block) (*certificates, *CertErrors) {

	var certs = &certificates{&sync.Mutex{}, nil}
	cerrs := &CertErrors{&sync.Mutex{}, nil}

	wg := &sync.WaitGroup{}

	for i, pc := range pemCerts {

		wg.Add(1)
		go func(i int, pc *pem.Block) {

			defer wg.Done()

			cert, err := x509.ParseCertificate(pc.Bytes)
			if err != nil {
				cerrs.addParseError(i, err)
			} else {
				certs.addCertificate(i, cert)
			}
		}(i, pc)
	}

	wg.Wait()

	return certs, cerrs
}
