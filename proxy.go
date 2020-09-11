// Copyright (C) 2016 JT Olds
// See LICENSE for copying information

package main

import (
	"crypto/tls"
	"io"
	"log"
	"net"
	"syscall"
	"time"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

func handleConn(inc net.Conn) {
	defer inc.Close()

	log.Printf("incoming connection from %s", inc.RemoteAddr())

	outc, err := net.Dial("tcp", *targetAddr)
	if err != nil {
		log.Println("failed forwarding request:", err)
		return
	}
	defer outc.Close()

	done := make(chan bool, 2)
	go proxy(outc, inc, done)
	go proxy(inc, outc, done)
	<-done
}

func proxy(outc io.Writer, inc io.Reader, done chan bool) {
	_, err := io.Copy(outc, inc)
	if err != nil && !isClosedConn(err) {
		log.Println("error forwarding stream:", err)
	}
	done <- true
}

func isClosedConn(err error) bool {
	if err == nil {
		return false
	}
	operr, ok := err.(*net.OpError)
	if !ok {
		return false
	}
	if operr.Err == syscall.ECONNRESET {
		return true
	}
	if operr.Err.Error() == "use of closed network connection" {
		return true
	}
	return false
}

func serve(manager *autocert.Manager) error {
	base_l, err := net.Listen("tcp", *listenAddr)
	if err != nil {
		log.Fatalf("failed listening on %s", *listenAddr)
	}
	defer base_l.Close()

	log.Printf("listening on %s", base_l.Addr())

	nextProtos := make([]string, 0, 3)
	if *supportHTTP2 {
		nextProtos = append(nextProtos, "h2")
	}
	nextProtos = append(nextProtos, "http/1.1", acme.ALPNProto)

	l := tls.NewListener(
		tcpKeepAliveListener{
			TCPListener: base_l.(*net.TCPListener)},
		&tls.Config{
			GetCertificate: manager.GetCertificate,
			NextProtos:     nextProtos,
		})

	var delay time.Duration
	for {
		conn, err := l.Accept()
		if err != nil {
			if nerr, ok := err.(net.Error); ok && nerr.Temporary() {
				if delay == 0 {
					delay = 5 * time.Millisecond
				} else {
					delay *= 2
				}
				if delay > time.Second {
					delay = time.Second
				}
				time.Sleep(delay)
				continue
			}
			return err
		}
		delay = 0
		go handleConn(conn)
	}
}
