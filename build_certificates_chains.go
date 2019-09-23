package sslbundle

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"sync"
)

type certChains struct {
	pb          *parsedBundle
	chains      [][]int
	hasNoLeaf   bool
	hasNoRoot   bool
	roots       map[int]bool
	leaves      []int
	bundleError *sslBundleError
}

// buildCertificateChains build chains of certificates by ensuring that for each chain:
//
// 1. The Issuer of each certificate (except the last one) matches the Subject
// of the next certificate in the list.
//
// 2. Each certificate (except the last one) is supposed to be signed by the
// secret key corresponding to the next certificate in the chain (i.e. the
// signature of one certificate can be verified using the public key contained
// in the following certificate).
//
// 3. The last certificate in the list is a trust anchor (self-signed): a certificate that you
// trust because it was delivered to you by some trustworthy procedure.
//
// More info at:
// - https://en.wikipedia.org/wiki/X.509#Certificate_chains_and_cross-certification
// - https://tools.ietf.org/html/rfc5280
// - http://www.oasis-pki.org/pdfs/Understanding_Path_construction-DS2.pdf
func buildCertificateChains(
	pb *parsedBundle,
	hostname string,
	privateKey []byte,
) *certChains {

	certs := pb.certs.certs
	cc := &certChains{
		pb:     pb,
		roots:  findRoots(certs),
		leaves: findLeaves(certs, hostname, privateKey, pb.pemCerts),
	}

	if len(cc.leaves) == 0 {
		cc.hasNoLeaf = true
	}

	if len(cc.roots) == 0 {
		cc.hasNoRoot = true
	}

	if cc.hasNoLeaf || cc.hasNoRoot {
		return cc
	}

	nodes := buildNodes(certs)
	cc.chains = buildChainsFrom(-1, cc.leaves, nodes)

	return cc
}

func buildChainsFrom(i int, parents []int, nodes map[int]*nodeCert) [][]int {

	// todo: avoid loop
	var chains [][]int
	mu := &sync.Mutex{}
	wg := &sync.WaitGroup{}

	for _, j := range parents {

		if i == j {
			continue
		}

		wg.Add(1)
		go func(j int) {

			defer wg.Done()

			chainsFromJ := buildChainsFrom(j, nodes[j].parents, nodes)

			if chainsFromJ == nil {
				mu.Lock()
				chains = append(chains, []int{j})
				mu.Unlock()
			}

			for _, chain := range chainsFromJ {
				chainFromJ := append([]int{j}, chain...)
				mu.Lock()
				chains = append(chains, chainFromJ)
				mu.Unlock()
			}
		}(j)
	}

	wg.Wait()

	return chains
}

type nodeCert struct {
	parents []int
}

func buildNodes(certs map[int]*x509.Certificate) map[int]*nodeCert {

	nodes := make(map[int]*nodeCert)

	wg := &sync.WaitGroup{}
	for i := range certs {
		nodes[i] = &nodeCert{}

		wg.Add(1)
		go func(i int, node *nodeCert) {

			defer wg.Done()

			for j, c := range certs {
				if certs[i].CheckSignatureFrom(c) == nil {

					if bytes.Equal(certs[i].RawIssuer, c.RawSubject) &&
						(i != j) {
						node.parents = append(node.parents, j)
					}
				}
			}
		}(i, nodes[i])
	}

	wg.Wait()
	return nodes
}

// findLeaves returns the leaf certificates found in the
// certificates provided.
//
// Valid leaves should match the hostname and
// be signed by the private key.
func findLeaves(
	certs map[int]*x509.Certificate,
	hostname string,
	privateKey []byte,
	pemCerts map[int]*pem.Block,
) []int {

	leaves := []int{}
	for i, c := range certs {
		if isLeaf(c, hostname, privateKey, pemCerts[i]) {
			leaves = append(leaves, i)
		}
	}
	return leaves
}

func isLeaf(
	cert *x509.Certificate,
	hostname string,
	privateKey []byte,
	pemCert *pem.Block,
) bool {

	pc := pem.EncodeToMemory(pemCert)

	if _, err := tls.X509KeyPair(pc, privateKey); err != nil {
		return false
	}

	if cert.VerifyHostname(hostname) == nil {
		return true
	}
	return false
}

// findRoots returns the root certificates found in the
// certificates provided.
func findRoots(certs map[int]*x509.Certificate) map[int]bool {

	roots := make(map[int]bool)
	for i, c := range certs {
		if isRoot(c) {
			roots[i] = true
		}
	}

	return roots
}

// isRoot returns a boolean indicating if the certificate is root.
//
// Any root certficate must be:
// - self-signed and having issuer and subject equal.
// More info at https://tools.ietf.org/html/rfc5280#section-4.2.1.9
func isRoot(cert *x509.Certificate) bool {

	isSelfSigned := func(cert *x509.Certificate) bool {
		// this will automatically check for v3 cert if IsCA true
		return cert.CheckSignatureFrom(cert) == nil
	}

	if isSelfSigned(cert) && bytes.Equal(cert.RawIssuer, cert.RawSubject) {
		return true
	}
	return false
}
