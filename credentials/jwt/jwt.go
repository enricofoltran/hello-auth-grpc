// Package jwt provides gRPC per-RPC credentials for JWT token authentication.
package jwt

import (
	"context"
	"fmt"
	"os"

	"google.golang.org/grpc/credentials"
)

// jwt implements the credentials.PerRPCCredentials interface for JWT tokens.
type jwt struct {
	token string
}

// NewFromTokenFile creates a JWT credential from a token file.
// The token file should contain a valid JWT token string.
func NewFromTokenFile(tokenPath string) (credentials.PerRPCCredentials, error) {
	data, err := os.ReadFile(tokenPath)
	if err != nil {
		return jwt{}, fmt.Errorf("could not read token file: %w", err)
	}

	if len(data) == 0 {
		return jwt{}, fmt.Errorf("token cannot be empty")
	}

	return jwt{string(data)}, nil
}

// GetRequestMetadata implements credentials.PerRPCCredentials.
// It adds the JWT token to the request metadata under the "authorization" key.
func (j jwt) GetRequestMetadata(ctx context.Context, uri ...string) (map[string]string, error) {
	return map[string]string{
		"authorization": j.token,
	}, nil
}

// RequireTransportSecurity implements credentials.PerRPCCredentials.
// It returns true to enforce that JWT tokens are only sent over secure connections.
func (j jwt) RequireTransportSecurity() bool {
	return true
}
