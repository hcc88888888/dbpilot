package main

import (
	"context"
	"errors"
	"flag"
	"io"
	"net"
	"os"
	"os/signal"
	"syscall"
)

func runNativeFixture(arguments []string, stderr io.Writer) int {
	flags := flag.NewFlagSet("native", flag.ContinueOnError)
	flags.SetOutput(stderr)
	address := flags.String("address", "", "exact loopback listen address")
	if flags.Parse(arguments) != nil || flags.NArg() != 0 || *address != "127.0.0.1:3306" {
		return 2
	}
	listener, err := net.Listen("tcp4", *address)
	if err != nil {
		return 1
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	return serveNativeFixture(ctx, listener)
}

func serveNativeFixture(ctx context.Context, listener net.Listener) int {
	if ctx == nil || listener == nil {
		return 2
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			_ = connection.Close()
		}
	}()
	<-ctx.Done()
	_ = listener.Close()
	<-done
	if !errors.Is(ctx.Err(), context.Canceled) {
		return 1
	}
	return 0
}
