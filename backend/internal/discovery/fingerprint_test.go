package discovery

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFingerprintIsPIDIndependentAndEndpointCanonical(t *testing.T) {
	left := CandidateObservation{Source: SourceNative, DatabaseFamily: "mysql", DatabaseVariant: "mysql", NormalizedEndpoint: "127.0.0.1:3306", ProcessIdentity: "mysqld"}
	right := left
	right.ObservationID = "pid-99999"
	right.NormalizedEndpoint = "127.000.000.001:3306"

	leftDigest, err := Fingerprint("host-1", left)
	require.NoError(t, err)
	rightDigest, err := Fingerprint("host-1", right)
	require.NoError(t, err)
	require.Equal(t, hex.EncodeToString(leftDigest[:]), hex.EncodeToString(rightDigest[:]))
}

func TestFingerprintSeparatesHostsAndRequiresStableIdentity(t *testing.T) {
	observation := CandidateObservation{Source: SourceNative, DatabaseFamily: "mysql", DatabaseVariant: "mysql", UnixSocket: "/run/mysqld/mysqld.sock", ServiceName: "mysqld.service"}
	left, err := Fingerprint("host-1", observation)
	require.NoError(t, err)
	right, err := Fingerprint("host-2", observation)
	require.NoError(t, err)
	require.NotEqual(t, left, right)

	_, err = Fingerprint("host-1", CandidateObservation{Source: SourceNative, DatabaseFamily: "mysql", DatabaseVariant: "mysql", ProcessIdentity: "mysqld"})
	require.ErrorIs(t, err, ErrInvalid)
}

func TestFingerprintPrefersEndpointWhenSocketEvidenceAppearsLater(t *testing.T) {
	endpointOnly := CandidateObservation{Source: SourceNative, DatabaseFamily: "mysql", DatabaseVariant: "mysql", NormalizedEndpoint: "127.0.0.1:3306", ProcessIdentity: "mysqld"}
	withSocket := endpointOnly
	withSocket.UnixSocket = "/run/mysqld/mysqld.sock"
	left, err := Fingerprint("host-1", endpointOnly)
	require.NoError(t, err)
	right, err := Fingerprint("host-1", withSocket)
	require.NoError(t, err)
	require.Equal(t, left, right)

	socketOnly := withSocket
	socketOnly.NormalizedEndpoint = ""
	fallback, err := Fingerprint("host-1", socketOnly)
	require.NoError(t, err)
	require.NotEqual(t, left, fallback, "socket-only identity is necessarily distinct when no stable endpoint exists")
}
