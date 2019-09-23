# SSL Bundle Validation

## Summary

SSL Bundle Validation builds all the possible chains from the available certificates
in the bundle, and returns the status of the bundle.

This is up to the consumer of this module to decide what constitutes a valid chain,
and to decide if the bundle validation is succesful based on the information provided.
<br><br>

A chain of certificates respects the following rules:

1. The first certificate of a chain is a leaf and matches the hostname provided. Its
associated public key matches the private key provided.

2. The Issuer of each certificate (except the last one) matches the Subject
of the next certificate in the chain.

3. Each certificate (except the last one) is signed by the secret key corresponding
to the next certificate in the chain (i.e. the signature of one certificate can be 
verified using the public key contained in the following certificate).

4. The last certificate in the chain is the root trust anchor (self-signed): a trustable
certificate delivered by some trustworthy procedure.
<br>

These chains can then be flagged according to specific criteria like:
* flagging a chain as expired if one of its certificate is expired
* flagging a chain as invalid if the last certificate is not a root certificate
<br><br>

## Architecture

Validating the SSL Bundle requires multiple steps described below:
<br><br>

### 1. Bundle Parsing: 

The PEM encoded bundle is parsed into its set of certificates. 
Any error happening during the parsing are recorded, and does not prevent to move to the next step.

### 2. Paths Construction: 

Certificate chains are being built if any from the set of valid certificates found in step (1).
Chains are required to have a valid leaf. Leaf must match the PEM encoded private key and hostname provided.

### 3. Paths Validation:

Chains are being parsed to be flagged according to specific criteria:
- Root must be self-signed and have their Issuer and Subject matching.
- Chains must not contain expired certificate(s).
<br><br>

## Installation
A recent Go version supporting Go modules needs to be installed.
<br><br>
This module is compatible with go1.13.
<br>
To test, simply run: `go test`
<br><br>

## Possible improvment:
* Loop detection in certificate chains.
* Writing a report regarding the bundle validity.
* Flagging chains could be done by checking other criteria:
  * Checking revocation status via OCST and CRL.
  * checking other constraints (path length, name, policy).
* Having the main trusted CA certificates, so that additional information
  could be provided regarding if the certificates would not generate any 
  warnings using the most popular browsers.
<br><br>

## Further lecture:
* OCST: https://tools.ietf.org/html/rfc6960.
* CRL: https://tools.ietf.org/html/rfc5280.
* https://en.wikipedia.org/wiki/X.509#Certificate_chains_and_cross-certification.
* Strategies to build and validate certificate chains: http://www.oasis-pki.org/pdfs/Understanding_Path_construction-DS2.pdf.