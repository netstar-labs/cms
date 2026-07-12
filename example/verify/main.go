// Copyright (C) 2026 zxdev
// SPDX-License-Identifier: GPL-3.0-or-later

// Command verify checks a detached CMS signature over a file against a PEM root
// bundle. Exit 0 and print the signer on success; exit 1 with the error on
// failure.
//
//	go run ./example/verify -content root-anchors.xml -sig root-anchors.p7s -roots icann-ca.pem
package main

import (
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/netstar-labs/cms"
)

func main() {
	contentPath := flag.String("content", "", "path to the signed content")
	sigPath := flag.String("sig", "", "path to the detached CMS signature (DER, .p7s)")
	rootsPath := flag.String("roots", "", "path to a PEM bundle of trusted root certificates")
	flag.Parse()

	if *contentPath == "" || *sigPath == "" || *rootsPath == "" {
		fmt.Fprintln(os.Stderr, "usage: verify -content <file> -sig <file.p7s> -roots <ca.pem>")
		os.Exit(2)
	}

	content := mustRead(*contentPath)
	sig := mustRead(*sigPath)
	roots := loadRoots(*rootsPath)

	signers, err := cms.Verify(content, sig, roots, time.Now())
	if err != nil {
		fmt.Fprintln(os.Stderr, "verify:", err)
		os.Exit(1)
	}
	for _, c := range signers {
		fmt.Printf("verified signer: %s\n", c.Subject)
	}
}

func mustRead(p string) []byte {
	b, err := os.ReadFile(p)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	return b
}

func loadRoots(p string) *x509.CertPool {
	pool := x509.NewCertPool()
	pemBytes := mustRead(p)
	for {
		var block *pem.Block
		block, pemBytes = pem.Decode(pemBytes)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			if c, err := x509.ParseCertificate(block.Bytes); err == nil {
				pool.AddCert(c)
			}
		}
	}
	return pool
}
