// Copyright (C) 2016 JT Olds
// See LICENSE for copying information

package main

import (
	"net"
	"os/user"
	"time"
)

func currentUser() *user.User {
	u, err := user.Current()
	if err != nil {
		panic(err)
	}
	return u
}

type tcpKeepAliveListener struct {
	*net.TCPListener
}

func (ln tcpKeepAliveListener) Accept() (c net.Conn, err error) {
	tc, err := ln.AcceptTCP()
	if err != nil {
		return nil, err
	}
	tc.SetKeepAlive(true)
	tc.SetKeepAlivePeriod(3 * time.Minute)
	return tc, nil
}
