package main

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestNativeFixtureOwnsARealLoopbackListenerUntilCancellation(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan int, 1)
	go func() { done <- serveNativeFixture(ctx, listener) }()
	connection, err := net.DialTimeout("tcp4", listener.Addr().String(), time.Second)
	require.NoError(t, err)
	require.NoError(t, connection.Close())
	cancel()
	require.Equal(t, 0, <-done)
}

func TestNativeFixtureRejectsAnyNonAcceptanceAddress(t *testing.T) {
	require.Equal(t, 2, runNativeFixture([]string{"--address", "0.0.0.0:3306"}, testWriter{}))
}

type testWriter struct{}

func (testWriter) Write(value []byte) (int, error) { return len(value), nil }
