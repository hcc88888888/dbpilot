package main

import (
	"net"
	"os"
	"strings"
)

func main() {
	port := "43307"
	for _, argument := range os.Args[1:] {
		if strings.HasPrefix(argument, "--port=") {
			port = strings.TrimPrefix(argument, "--port=")
		}
	}
	listener, err := net.Listen("tcp", "127.0.0.1:"+port)
	if err != nil {
		panic(err)
	}
	defer listener.Close()
	for {
		connection, err := listener.Accept()
		if err != nil {
			return
		}
		_ = connection.Close()
	}
}
