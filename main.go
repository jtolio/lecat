// Copyright (C) 2016 JT Olds
// See LICENSE for copying information

package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"runtime"
	"time"

	"golang.org/x/crypto/acme/autocert"
)

var (
	reachableHost = flag.String("host", "",
		"the hostname to get a certificate for. something like "+
			"'yourservice.yourdomain.tld'")
	listenAddr = flag.String("addr", ":443", "the address to listen on. "+
		"this almost certainly should be ':443'")
	targetAddr = flag.String("target", "",
		"the address to forward unencrypted connections to. "+
			"probably something like 'localhost:8080'")
	statePath = flag.String("path", os.ExpandEnv("$HOME/.lecat"),
		"the path to a folder to keep state.")
	redirectAddr = flag.String("redirect-addr", "",
		"if set, will listen on this address and redirect unencrypted http "+
			"requests to it to https AND set HSTS. if you want this at "+
			"all, you almost certainly want ':80'")
	hstsDuration = flag.Duration("hsts-duration", 24*time.Hour,
		"if redirect-addr is set, length of time to trigger hsts")
	acceptTOS    = flag.Bool("accept-tos", false, "if true, accept lets encrypt TOS")
	supportHTTP2 = flag.Bool("support-http2", false,
		"if true, indicate http2 support in the ssl handshake")
	email = flag.String("email", "", "the email address to use with letsencrypt")
)

func AcceptTOS(url string) bool {
	if *acceptTOS {
		return true
	}
	fmt.Println("Do you accept the Let's Encrypt terms of service?")
	fmt.Println(url)
	fmt.Println("Press enter to accept, control-c to reject")
	_, err := bufio.NewReader(os.Stdin).ReadString('\n')
	return err == nil
}

func main() {
	flag.Parse()
	runtime.GOMAXPROCS(runtime.NumCPU() + 1)

	if *reachableHost == "" {
		log.Fatal("--host argument required")
	}

	if *targetAddr == "" {
		log.Fatal("--target argument required")
	}

	manager := &autocert.Manager{
		Prompt:     AcceptTOS,
		HostPolicy: autocert.HostWhitelist(*reachableHost),
		Email:      *email,
	}

	log.Println("loading configuration")

	err := os.MkdirAll(*statePath, 0700)
	if err != nil {
		log.Fatal("failed to make state path:", err)
	}
	manager.Cache = autocert.DirCache(*statePath)

	if *redirectAddr != "" {
		go func() {
			log.Printf("redirecting on %s", *redirectAddr)
			panic(http.ListenAndServe(*redirectAddr, http.HandlerFunc(
				func(w http.ResponseWriter, req *http.Request) {
					log.Printf("redirecting request from %s and setting HSTS",
						req.RemoteAddr)
					w.Header().Set("Strict-Transport-Security", fmt.Sprintf("max-age=%d", int64(hstsDuration.Seconds())))
					http.Redirect(w, req,
						fmt.Sprintf("https://%s%s", *reachableHost, req.RequestURI),
						http.StatusMovedPermanently)
				})))
		}()
	}

	panic(serve(manager))
}
