//go:build !linux

package discovery

import (
	"context"
	"errors"

	domain "dbpilot.local/platform/internal/discovery"
)

var ErrNativeDiscoveryUnsupported = errors.New("native discovery is supported only on Linux")

type ProcessObservation struct {
	PID int
}

type EndpointObservation struct {
	Network string
	Address string
}

type NativeReader interface {
	Processes(context.Context) ([]ProcessObservation, error)
	ListeningEndpoints(context.Context, int) ([]EndpointObservation, error)
	SystemdUnit(context.Context, int) (string, bool, error)
	ProcessStartTime(context.Context, int) (uint64, error)
}

type ProcReader struct{}

func NewProcReader(string, interface{}) *ProcReader       { return &ProcReader{} }
func NewLegacyProcReader(string, interface{}) *ProcReader { return &ProcReader{} }
func RunLegacyProcHelper(context.Context, uint32, uint32, []string) error {
	return ErrNativeDiscoveryUnsupported
}
func (*ProcReader) Processes(context.Context) ([]ProcessObservation, error) {
	return nil, ErrNativeDiscoveryUnsupported
}
func (*ProcReader) ListeningEndpoints(context.Context, int) ([]EndpointObservation, error) {
	return nil, ErrNativeDiscoveryUnsupported
}
func (*ProcReader) SystemdUnit(context.Context, int) (string, bool, error) {
	return "", false, ErrNativeDiscoveryUnsupported
}
func (*ProcReader) ProcessStartTime(context.Context, int) (uint64, error) {
	return 0, ErrNativeDiscoveryUnsupported
}

type NativeDetector struct{ reader NativeReader }

func NewNativeDetector(reader NativeReader) *NativeDetector { return &NativeDetector{reader: reader} }
func (*NativeDetector) Discover(context.Context, []domain.Rule) ([]domain.CandidateObservation, error) {
	return nil, ErrNativeDiscoveryUnsupported
}
