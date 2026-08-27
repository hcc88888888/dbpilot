//go:build smtp_sink

package main

import (
	"bufio"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/textproto"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"
)

const maximumMessageBytes = 1 << 20

type smtpRecord struct {
	EnvelopeHash string `json:"envelope_hash"`
	BodyHash     string `json:"body_hash"`
}

func main() {
	listen := flag.String("listen", ":2465", "implicit-TLS SMTP listen address")
	certFile := flag.String("cert", "", "TLS certificate")
	keyFile := flag.String("key", "", "TLS private key")
	stateDirectory := flag.String("state", "/state", "hash-only state directory")
	checkAddress := flag.String("check", "", "perform a TLS health check and exit")
	caFile := flag.String("ca", "", "health-check CA")
	serverName := flag.String("server-name", "smtp-sink", "health-check TLS server name")
	flag.Parse()
	if *checkAddress != "" {
		if err := checkTLS(*checkAddress, *caFile, *serverName); err != nil {
			log.Print("SMTP health check failed")
			os.Exit(1)
		}
		return
	}
	password, ok := os.LookupEnv("ALERT_SMTP_PASSWORD")
	if !ok || password == "" {
		log.Fatal("SMTP fixture password is unavailable")
	}
	if err := os.MkdirAll(*stateDirectory, 0o700); err != nil {
		log.Fatal("create SMTP state directory failed")
	}
	certificate, err := tls.LoadX509KeyPair(*certFile, *keyFile)
	if err != nil {
		log.Fatal("load SMTP TLS material failed")
	}
	listener, err := tls.Listen("tcp", *listen, &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12})
	if err != nil {
		log.Fatal("start SMTP fixture failed")
	}
	defer listener.Close()
	log.Print("SMTP fixture ready")
	var sequence atomic.Uint64
	for {
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			log.Print("SMTP accept failed")
			continue
		}
		go func() {
			defer connection.Close()
			if err := serveSMTP(connection, password, *stateDirectory, sequence.Add(1)); err != nil && !errors.Is(err, io.EOF) {
				log.Print("SMTP session ended without recording a message")
			}
		}()
	}
}

func checkTLS(address, caFile, serverName string) error {
	pem, err := os.ReadFile(caFile)
	if err != nil {
		return err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		return errors.New("CA contains no certificates")
	}
	connection, err := tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp", address, &tls.Config{RootCAs: roots, ServerName: serverName, MinVersion: tls.VersionTLS12})
	if err != nil {
		return err
	}
	return connection.Close()
}

func serveSMTP(connection net.Conn, password, stateDirectory string, sequence uint64) error {
	reader := bufio.NewReader(io.LimitReader(connection, 2<<20))
	writer := bufio.NewWriter(connection)
	write := func(line string) error {
		if _, err := writer.WriteString(line + "\r\n"); err != nil {
			return err
		}
		return writer.Flush()
	}
	if err := write("220 smtp-sink ESMTP"); err != nil {
		return err
	}
	authenticated := false
	mailFrom, recipient := "", ""
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return err
		}
		line = strings.TrimSpace(line)
		command, argument, _ := strings.Cut(line, " ")
		switch strings.ToUpper(command) {
		case "EHLO", "HELO":
			if _, err := writer.WriteString("250-smtp-sink\r\n250-AUTH PLAIN\r\n250 SIZE 1048576\r\n"); err != nil {
				return err
			}
			if err := writer.Flush(); err != nil {
				return err
			}
		case "AUTH":
			parts := strings.Fields(argument)
			if len(parts) != 2 || strings.ToUpper(parts[0]) != "PLAIN" || !validPlainAuth(parts[1], password) {
				if err := write("535 5.7.8 Authentication credentials invalid"); err != nil {
					return err
				}
				continue
			}
			authenticated = true
			if err := write("235 2.7.0 Authentication successful"); err != nil {
				return err
			}
		case "MAIL":
			if !authenticated {
				if err := write("530 5.7.0 Authentication required"); err != nil {
					return err
				}
				continue
			}
			mailFrom = argument
			if err := write("250 2.1.0 OK"); err != nil {
				return err
			}
		case "RCPT":
			recipient = argument
			if err := write("250 2.1.5 OK"); err != nil {
				return err
			}
		case "DATA":
			if !authenticated || mailFrom == "" || recipient == "" {
				if err := write("503 5.5.1 Bad sequence of commands"); err != nil {
					return err
				}
				continue
			}
			if err := write("354 End data with <CR><LF>.<CR><LF>"); err != nil {
				return err
			}
			bodyHash := sha256.New()
			read, err := io.Copy(bodyHash, io.LimitReader(textproto.NewReader(reader).DotReader(), maximumMessageBytes+1))
			if err != nil || read > maximumMessageBytes {
				return errors.New("invalid SMTP message")
			}
			envelope := sha256.Sum256([]byte(mailFrom + "\x00" + recipient))
			record := smtpRecord{EnvelopeHash: hex.EncodeToString(envelope[:]), BodyHash: hex.EncodeToString(bodyHash.Sum(nil))}
			if err := persistRecord(stateDirectory, fmt.Sprintf("smtp-%020d.json", sequence), record); err != nil {
				return err
			}
			if err := write("250 2.0.0 Accepted"); err != nil {
				return err
			}
		case "QUIT":
			_ = write("221 2.0.0 Bye")
			return nil
		default:
			if err := write("250 OK"); err != nil {
				return err
			}
		}
	}
}

func validPlainAuth(encoded, password string) bool {
	value, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return false
	}
	parts := strings.Split(string(value), "\x00")
	return len(parts) == 3 && parts[1] == "fixture" && parts[2] == password
}

func persistRecord(directory, name string, value any) error {
	body, err := json.Marshal(value)
	if err != nil {
		return err
	}
	temporary, err := os.CreateTemp(directory, ".record-")
	if err != nil {
		return err
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(body); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporaryName, filepath.Join(directory, name))
}
