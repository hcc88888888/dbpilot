package controlplane

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"strings"
)

type traceIDContextKey struct{}

func withTraceContext(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		traceparent, traceID := validTraceparent(request.Header.Values("traceparent"))
		if traceparent == "" {
			traceparent, traceID = newTraceparent()
		}
		writer.Header().Set("traceparent", traceparent)
		ctx := context.WithValue(request.Context(), traceIDContextKey{}, traceID)
		next.ServeHTTP(writer, request.WithContext(ctx))
	})
}

func traceIDFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	value, _ := ctx.Value(traceIDContextKey{}).(string)
	return value
}

func validTraceparent(values []string) (string, string) {
	if len(values) != 1 || values[0] != strings.ToLower(strings.TrimSpace(values[0])) {
		return "", ""
	}
	parts := strings.Split(values[0], "-")
	if len(parts) != 4 || len(parts[0]) != 2 || parts[0] == "ff" || len(parts[1]) != 32 || len(parts[2]) != 16 || len(parts[3]) != 2 || allZeroHex(parts[1]) || allZeroHex(parts[2]) {
		return "", ""
	}
	for _, part := range parts {
		if _, err := hex.DecodeString(part); err != nil {
			return "", ""
		}
	}
	if parts[0] == "00" && len(values[0]) != 55 {
		return "", ""
	}
	return values[0], parts[1]
}

func allZeroHex(value string) bool { return strings.Trim(value, "0") == "" }

func newTraceparent() (string, string) {
	trace := make([]byte, 16)
	parent := make([]byte, 8)
	if _, err := rand.Read(trace); err != nil {
		trace[15] = 1
	}
	if _, err := rand.Read(parent); err != nil {
		parent[7] = 1
	}
	if allZeroBytes(trace) {
		trace[15] = 1
	}
	if allZeroBytes(parent) {
		parent[7] = 1
	}
	traceID := hex.EncodeToString(trace)
	return "00-" + traceID + "-" + hex.EncodeToString(parent) + "-01", traceID
}

func allZeroBytes(value []byte) bool {
	for _, item := range value {
		if item != 0 {
			return false
		}
	}
	return true
}
