// Copyright (C) 2016 JT Olds
// See LICENSE for copying information

package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"
)

func createKey(name string) (key *rsa.PrivateKey, err error) {
	log.Printf("no key found at %s/%s.key, generating", *statePath, name)
	key, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(*statePath, fmt.Sprintf("%s.key", name)),
		os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	err = pem.Encode(f, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key)})
	if err != nil {
		return nil, err
	}
	return key, nil
}

func loadKey(name string) (*rsa.PrivateKey, error) {
	pem_bytes, err := ioutil.ReadFile(
		filepath.Join(*statePath, fmt.Sprintf("%s.key", name)))
	if err != nil {
		if os.IsNotExist(err) {
			return createKey(name)
		}
		return nil, err
	}
	var pem_block *pem.Block
	for {
		pem_block, pem_bytes = pem.Decode(pem_bytes)
		if pem_block == nil || pem_bytes == nil {
			return nil, fmt.Errorf("no pem data found")
		}
		if pem_block.Type == "PRIVATE KEY" ||
			strings.HasSuffix(pem_block.Type, " PRIVATE KEY") {
			break
		}
	}
	return x509.ParsePKCS1PrivateKey(pem_block.Bytes)
}
