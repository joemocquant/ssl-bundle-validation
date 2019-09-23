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

type parsedBundle struct {
	be       *bundleError
	certs    *certificates
	pemCerts map[int]*pem.Block
}

type bundleError struct {
	berrs blockErrors
	cerrs *certErrors
}

// blockErrors is a map to handle PEM block errors.
type blockErrors map[int]*blockError

type blockError struct {
	IsNotCertificate    bool
	blockContainsHeader bool
}

// certErrors is a concurrent map to handle certificate errors.
type certErrors struct {
	*sync.Mutex
	errs map[int]*certError
}

type certError struct {
	parseErr error
}

func (cerrs *certErrors) addParseError(i int, err error) {
	cerrs.Lock()
	defer cerrs.Unlock()

	if cerrs.errs == nil {
		cerrs.errs = make(map[int]*certError)
	}
	cerrs.errs[i] = &certError{parseErr: err}
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
func parseSSLBundle(bundle []byte) *parsedBundle {

	pemCerts, berrs := extractPEMCerts(bundle)
	certs, cerrs := parsePEMCertificates(pemCerts)

	return &parsedBundle{&bundleError{berrs, cerrs}, certs, pemCerts}
}

// extractPEMCerts decodes the SSL bundle provided into an array of PEM
// Certs. It also returns any errors encountered during decoding.
func extractPEMCerts(bundle []byte) (map[int]*pem.Block, blockErrors) {
	return extractPEMValues(bundle, []blockType{certificate})
}

// extractPEMValues decodes the SSL bundle provided into an array of PEM
// Values. PEM values to decode are passed as a parameter.
// It also returns any errors encountered during decoding.
func extractPEMValues(
	bundle []byte,
	allowedBlockTypes []blockType,
) (map[int]*pem.Block, blockErrors) {

	pemValues := make(map[int]*pem.Block)
	berrs := make(blockErrors)

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
			berrs[blockCount] = &blockError{true, false}
		}

		if len(block.Headers) != 0 {
			berrs[blockCount] = &blockError{false, true}
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
func parsePEMCertificates(pemCerts map[int]*pem.Block) (*certificates, *certErrors) {

	var certs = &certificates{&sync.Mutex{}, nil}
	cerrs := &certErrors{&sync.Mutex{}, nil}

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
