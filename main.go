// Copyright (C) 2016 JT Olds
// See LICENSE for copying information

package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
)

var (
	// staging server: https://acme-staging.api.letsencrypt.org/directory
	// production server: https://acme-v01.api.letsencrypt.org/directory
	apiServer = flag.String("letsencrypt.api_server",
		"https://acme-v01.api.letsencrypt.org/directory",
		"letsencrypt api server")
	reachableHost = flag.String("host", "",
		"the hostname to get a certificate for. something like "+
			"'yourservice.yourdomain.tld'")
	listenAddr = flag.String("addr", ":443", "the address to listen on. "+
		"this almost certainly should be ':443'")
	targetAddr = flag.String("target", "",
		"the address to forward unencrypted connections to. "+
			"probably something like 'localhost:8080'")
	statePath = flag.String("path",
		filepath.Join(os.Getenv("HOME"), ".lecat"),
		"the path to a folder to keep state. If you already have a "+
			"letsencrypt account key, please name it 'account.key' in this folder.")
	redirectAddr = flag.String("redirect-addr", "",
		"if set, will listen on this address and redirect unencrypted http "+
			"requests to it to https AND set HSTS for a year. if you want this at "+
			"all, you almost certainly want ':80'")
)

func main() {
	flag.Parse()
	runtime.GOMAXPROCS(runtime.NumCPU() + 1)

	if *reachableHost == "" {
		log.Fatal("--host argument required")
	}

	if *targetAddr == "" {
		log.Fatal("--target argument required")
	}

	log.Println("loading configuration")

	err := os.MkdirAll(*statePath, 0700)
	if err != nil {
		log.Fatal("failed to make state path:", err)
	}

	key, err := loadKey("server")
	if err != nil {
		log.Fatal("failed to load server key:", err)
	}

	cert, err := loadServerCert(key)
	if err != nil {
		log.Fatal("failed to load or create server cert:", err)
	}

	if *redirectAddr != "" {
		go func() {
			log.Printf("redirecting on %s", *redirectAddr)
			panic(http.ListenAndServe(*redirectAddr, http.HandlerFunc(
				func(w http.ResponseWriter, req *http.Request) {
					log.Printf("redirecting request from %s and setting HSTS",
						req.RemoteAddr)
					w.Header().Set("Strict-Transport-Security", "max-age=31536000")
					http.Redirect(w, req,
						fmt.Sprintf("https://%s%s", *reachableHost, req.RequestURI),
						http.StatusMovedPermanently)
				})))
		}()
	}

	panic(serve(key, cert))
}
