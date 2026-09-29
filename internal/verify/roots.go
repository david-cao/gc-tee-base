package verify

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"

	_ "embed"
)

// Google's EK/AK CA for GCE vTPM attestation keys ("CN=EK/AK CA Root" /
// "CN=EK/AK CA Intermediate"). Vendored from go-tpm-tools v0.4.10
// server/ca-certs/, which embeds these files but never exposes them:
// server.GceEKRoots exports only the legacy tpm_ek_root_1 EK root, which
// modern GCE AK certificates do NOT chain to (verified against a live
// Confidential VM on 2026-09-29; the root here is byte-identical to the CA
// certificate Google serves at the intermediate's issuingCertificateURL).
//
//go:embed ca-certs/gcp_ek_ak_ca_root.crt
var gceAKRootPEM []byte

//go:embed ca-certs/gcp_ek_ak_ca_intermediate_v3.crt
var gceAKIntermediatePEM []byte

// GceAKRoots and GceAKIntermediates are the trust anchors for Google-issued
// vTPM attestation key certificates. Evidence normally carries its own
// (possibly newer, regional) intermediate, which VerifyAttestation appends;
// the bundled intermediate is a fallback.
var (
	GceAKRoots         []*x509.Certificate
	GceAKIntermediates []*x509.Certificate
)

func init() {
	var err error
	GceAKRoots, err = parsePEMOrDERCerts(gceAKRootPEM)
	if err != nil {
		panic(fmt.Sprintf("parsing bundled GCE AK root CA: %v", err))
	}
	GceAKIntermediates, err = parsePEMOrDERCerts(gceAKIntermediatePEM)
	if err != nil {
		panic(fmt.Sprintf("parsing bundled GCE AK intermediate CA: %v", err))
	}
}

func parsePEMOrDERCerts(data []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	rest := data
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		certs = append(certs, cert)
	}
	if len(certs) > 0 {
		return certs, nil
	}
	cert, err := x509.ParseCertificate(data)
	if err != nil {
		return nil, err
	}
	return []*x509.Certificate{cert}, nil
}
