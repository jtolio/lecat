// Copyright (C) 2016 JT Olds
// See LICENSE for copying information

package main

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net/http"
	"sync"

	"github.com/ericchiang/letsencrypt"
)

func requestServerCert(serverKey *rsa.PrivateKey) (*x509.Certificate, error) {
	accountKey, err := loadKey("account")
	if err != nil {
		return nil, err
	}

	cli, err := letsencrypt.NewClient(*apiServer)
	if err != nil {
		return nil, err
	}

	log.Printf("(re)registering account key")
	_, err = cli.NewRegistration(accountKey)
	if err != nil {
		return nil, err
	}

	log.Printf("getting challenges for %#v", *reachableHost)
	// ask for a set of challenges for a given domain
	auth, _, err := cli.NewAuthorization(accountKey, "dns", *reachableHost)
	if err != nil {
		return nil, err
	}

	chals := auth.Combinations(letsencrypt.ChallengeTLSSNI)
	if len(chals) != 1 && len(chals[0]) != 1 {
		return nil, fmt.Errorf("no supported challenge combinations")
	}

	log.Printf("performing sni challenge")
	chal := chals[0][0]
	if chal.Type != letsencrypt.ChallengeTLSSNI {
		return nil, fmt.Errorf("not a tls sni challenge")
	}

	certs, err := chal.TLSSNI(accountKey)
	if err != nil {
		return nil, err
	}

	getCertificate := func(clientHello *tls.ClientHelloInfo) (
		*tls.Certificate, error) {
		if cert, ok := certs[clientHello.ServerName]; ok {
			return cert, nil
		}
		return nil, nil
	}

	selfSigned, err := selfSignedCert(serverKey)
	if err != nil {
		return nil, err
	}

	config := &tls.Config{
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{selfSigned.Raw},
			PrivateKey:  serverKey,
			Leaf:        selfSigned}},
		NextProtos:     []string{"http/1.1"},
		GetCertificate: getCertificate}

	l, err := tls.Listen("tcp", *listenAddr, config)
	if err != nil {
		return nil, err
	}
	defer l.Close()

	var wg sync.WaitGroup
	wg.Add(1)

	go func() {
		defer wg.Done()
		(&http.Server{Handler: http.HandlerFunc(http.NotFound)}).Serve(l)
	}()

	log.Printf("waiting for challenge")
	err = cli.ChallengeReady(accountKey, chal)
	if err != nil {
		return nil, err
	}

	log.Printf("making csr")
	csr, err := newCSR(serverKey)
	if err != nil {
		return nil, err
	}

	log.Printf("getting cert")
	res, err := cli.NewCertificate(accountKey, csr)
	if err != nil {
		return nil, err
	}

	l.Close()
	wg.Wait()

	return res.Certificate, nil
}
