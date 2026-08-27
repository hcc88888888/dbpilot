package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io"
	"net"
	"os"

	telemetryv1 "dbpilot.local/platform/gen/agent/v1"
	"dbpilot.local/platform/internal/ingest"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

const version = "dev"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("dbpilot-telemetry-test-gateway", flag.ContinueOnError)
	flags.SetOutput(stderr)
	showVersion := flags.Bool("version", false, "print version and exit")
	listen := flags.String("listen", "127.0.0.1:9443", "TLS listen address (loopback by default)")
	caFile := flags.String("ca", "", "required PEM CA used to verify client certificates")
	certFile := flags.String("cert", "", "required PEM server certificate")
	keyFile := flags.String("key", "", "required PEM server private key")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *showVersion {
		fmt.Fprintln(stdout, version)
		return 0
	}
	if *caFile == "" || *certFile == "" || *keyFile == "" {
		fmt.Fprintln(stderr, "--ca, --cert, and --key are required; plaintext mode is not supported")
		return 2
	}
	config, err := serverTLSConfig(*caFile, *certFile, *keyFile)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	listener, err := net.Listen("tcp", *listen)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	defer listener.Close()
	server := grpc.NewServer(grpc.Creds(credentials.NewTLS(config)))
	telemetryv1.RegisterTelemetryIngestServer(server, ingest.NewService(ingest.AllowAnyVerifiedAgent{}, ingest.NewMemoryDeduplicator()))
	if err := server.Serve(listener); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	return 0
}

func serverTLSConfig(caFile, certFile, keyFile string) (*tls.Config, error) {
	caPEM, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("read client CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("read client CA: no certificates in %s", caFile)
	}
	certificate, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load server certificate/key: %w", err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{certificate},
		ClientCAs:    pool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS12,
	}, nil
}
