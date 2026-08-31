//go:build !linux

package plugingateway

import (
	"context"
	"errors"

	"google.golang.org/grpc"
)

var errGatewayUnsupported = errors.New("PLUGIN_GATEWAY_UNSUPPORTED")

func verifyPrivateRuntimeRoot(string) error { return errGatewayUnsupported }
func dialVerifiedPlugin(context.Context, string, ExpectedPlugin) (*grpc.ClientConn, error) {
	return nil, errGatewayUnsupported
}
