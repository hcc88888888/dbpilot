//go:build webhook_sink

package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
	"time"
)

const maximumWebhookBytes int64 = 1 << 20

type webhookRecord struct {
	HeadersHash string `json:"headers_hash"`
	BodyHash    string `json:"body_hash"`
}

type fixtureStatus struct {
	WebhookAttempts   int      `json:"webhook_attempts"`
	SMTPMessages      int      `json:"smtp_messages"`
	WebhookBodyHashes []string `json:"webhook_body_hashes"`
	SMTPBodyHashes    []string `json:"smtp_body_hashes"`
}

func main() {
	listen := flag.String("listen", ":8443", "HTTPS listen address")
	certFile := flag.String("cert", "", "TLS certificate")
	keyFile := flag.String("key", "", "TLS private key")
	stateDirectory := flag.String("state", "/state", "hash-only state directory")
	checkURL := flag.String("check-url", "", "perform an HTTPS health check and exit")
	caFile := flag.String("ca", "", "health-check CA")
	clientCert := flag.String("client-cert", "", "optional health-check client certificate")
	clientKey := flag.String("client-key", "", "optional health-check client key")
	flag.Parse()
	if *checkURL != "" {
		if err := checkHTTPS(*checkURL, *caFile, *clientCert, *clientKey); err != nil {
			log.Print("HTTPS health check failed")
			os.Exit(1)
		}
		return
	}
	secret, ok := os.LookupEnv("ALERT_WEBHOOK_SECRET")
	if !ok || secret == "" {
		log.Fatal("Webhook fixture secret is unavailable")
	}
	if err := os.MkdirAll(*stateDirectory, 0o700); err != nil {
		log.Fatal("create Webhook state directory failed")
	}
	var attempts atomic.Uint64
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("GET /status", func(writer http.ResponseWriter, _ *http.Request) {
		status, err := readStatus(*stateDirectory, int(attempts.Load()))
		if err != nil {
			http.Error(writer, "status unavailable", http.StatusInternalServerError)
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(writer).Encode(status)
	})
	mux.HandleFunc("POST /hook/retry", func(writer http.ResponseWriter, request *http.Request) {
		body, err := io.ReadAll(io.LimitReader(request.Body, maximumWebhookBytes+1))
		if err != nil || int64(len(body)) > maximumWebhookBytes || !validSignature(request, body, []byte(secret)) {
			http.Error(writer, "invalid delivery", http.StatusBadRequest)
			return
		}
		attempt := attempts.Add(1)
		bodyDigest := sha256.Sum256(body)
		headerDigest := sha256.Sum256(canonicalHeaders(request.Header))
		record := webhookRecord{HeadersHash: hex.EncodeToString(headerDigest[:]), BodyHash: hex.EncodeToString(bodyDigest[:])}
		if err := persistRecord(*stateDirectory, formatRecordName("webhook", attempt), record); err != nil {
			http.Error(writer, "record unavailable", http.StatusInternalServerError)
			return
		}
		if attempt == 1 {
			http.Error(writer, "retry", http.StatusServiceUnavailable)
			return
		}
		writer.WriteHeader(http.StatusNoContent)
	})
	server := &http.Server{Addr: *listen, Handler: mux, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 32 << 10}
	log.Print("Webhook fixture ready")
	if err := server.ListenAndServeTLS(*certFile, *keyFile); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal("start Webhook fixture failed")
	}
}

func checkHTTPS(rawURL, caFile, certFile, keyFile string) error {
	pem, err := os.ReadFile(caFile)
	if err != nil {
		return err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		return errors.New("CA contains no certificates")
	}
	tlsConfig := &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
	if certFile != "" || keyFile != "" {
		certificate, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return err
		}
		tlsConfig.Certificates = []tls.Certificate{certificate}
	}
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: tlsConfig}, Timeout: 5 * time.Second}
	response, err := client.Get(rawURL)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return errors.New("unhealthy HTTP status")
	}
	return nil
}

func validSignature(request *http.Request, body, secret []byte) bool {
	provided := request.Header.Get("X-DBPilot-Signature")
	if !strings.HasPrefix(provided, "sha256=") || request.Header.Get("X-DBPilot-Timestamp") == "" {
		return false
	}
	decoded, err := hex.DecodeString(strings.TrimPrefix(provided, "sha256="))
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write(body)
	return hmac.Equal(decoded, mac.Sum(nil))
}

func canonicalHeaders(headers http.Header) []byte {
	keys := []string{"Content-Type", "X-DBPilot-Signature", "X-DBPilot-Timestamp"}
	sort.Strings(keys)
	var canonical bytes.Buffer
	for _, key := range keys {
		canonical.WriteString(strings.ToLower(key))
		canonical.WriteByte(':')
		canonical.WriteString(headers.Get(key))
		canonical.WriteByte('\n')
	}
	return canonical.Bytes()
}

func readStatus(directory string, attempts int) (fixtureStatus, error) {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return fixtureStatus{}, err
	}
	status := fixtureStatus{WebhookAttempts: attempts, WebhookBodyHashes: []string{}, SMTPBodyHashes: []string{}}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		body, err := os.ReadFile(filepath.Join(directory, entry.Name()))
		if err != nil {
			return fixtureStatus{}, err
		}
		if strings.HasPrefix(entry.Name(), "webhook-") {
			var record webhookRecord
			if json.Unmarshal(body, &record) == nil && record.BodyHash != "" {
				status.WebhookBodyHashes = append(status.WebhookBodyHashes, record.BodyHash)
			}
		}
		if strings.HasPrefix(entry.Name(), "smtp-") {
			var record struct {
				BodyHash string `json:"body_hash"`
			}
			if json.Unmarshal(body, &record) == nil && record.BodyHash != "" {
				status.SMTPBodyHashes = append(status.SMTPBodyHashes, record.BodyHash)
				status.SMTPMessages++
			}
		}
	}
	sort.Strings(status.WebhookBodyHashes)
	sort.Strings(status.SMTPBodyHashes)
	return status, nil
}

func formatRecordName(prefix string, sequence uint64) string {
	const digits = "00000000000000000000"
	value := fmtUint(sequence)
	return prefix + "-" + digits[:len(digits)-len(value)] + value + ".json"
}

func fmtUint(value uint64) string {
	if value == 0 {
		return "0"
	}
	var buffer [20]byte
	index := len(buffer)
	for value > 0 {
		index--
		buffer[index] = byte('0' + value%10)
		value /= 10
	}
	return string(buffer[index:])
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
