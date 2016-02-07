// Copyright (C) 2016 JT Olds
// See LICENSE for copying information

package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

func loadServerCert(serverKey *rsa.PrivateKey) (*x509.Certificate, error) {
	pem_bytes, err := ioutil.ReadFile(filepath.Join(*statePath, "server.crt"))
	if err != nil {
		if os.IsNotExist(err) {
			return createServerCert(serverKey)
		}
		return nil, err
	}
	var pem_block *pem.Block
	for {
		pem_block, pem_bytes = pem.Decode(pem_bytes)
		if pem_block == nil || pem_bytes == nil {
			return nil, fmt.Errorf("no pem data found")
		}
		if pem_block.Type == "CERTIFICATE" {
			break
		}
	}
	return x509.ParseCertificate(pem_block.Bytes)
}

func createServerCert(serverKey *rsa.PrivateKey) (*x509.Certificate, error) {
	log.Printf("no cert found at %s/server.crt, requesting", *statePath)
	cert, err := requestServerCert(serverKey)
	if err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(*statePath, "server.crt"),
		os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	err = pem.Encode(f, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw})
	if err != nil {
		return nil, err
	}
	return cert, nil
}

func selfSignedCert(key *rsa.PrivateKey) (*x509.Certificate, error) {
	not_before := time.Now().Add(-24 * time.Hour)
	not_after := time.Now().Add(24 * time.Hour)

	serial, err := rand.Int(rand.Reader,
		new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}

	template := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{Organization: []string{"self-signed"}},
		NotBefore:             not_before,
		NotAfter:              not_after,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{*reachableHost},
		IsCA:                  true,
		KeyUsage: (x509.KeyUsageKeyEncipherment |
			x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign),
	}

	der_bytes, err := x509.CreateCertificate(rand.Reader, &template, &template,
		&key.PublicKey, key)
	if err != nil {
		return nil, err
	}

	return x509.ParseCertificate(der_bytes)
}

func newCSR(serverKey *rsa.PrivateKey) (*x509.CertificateRequest, error) {
	template := &x509.CertificateRequest{
		SignatureAlgorithm: x509.SHA256WithRSA,
		PublicKeyAlgorithm: x509.RSA,
		PublicKey:          &serverKey.PublicKey,
		Subject:            pkix.Name{CommonName: *reachableHost},
		DNSNames:           []string{*reachableHost},
	}
	csrDER, err := x509.CreateCertificateRequest(
		rand.Reader, template, serverKey)
	if err != nil {
		return nil, err
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return nil, err
	}
	return csr, nil
}
