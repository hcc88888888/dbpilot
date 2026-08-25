package main

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGatewayRefusesToStartWithoutExplicitMTLSMaterial(t *testing.T) {
	assert.Equal(t, 2, run(nil, &bytes.Buffer{}, &bytes.Buffer{}))
}
