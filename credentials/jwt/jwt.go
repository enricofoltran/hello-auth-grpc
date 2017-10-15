package jwt

import (
	"fmt"
	"io/ioutil"

	"golang.org/x/net/context"
	"google.golang.org/grpc/credentials"
)

type jwt struct {
	token string
}

// NewFromTokenFile return a jwt credential
func NewFromTokenFile(token string) (credentials.PerRPCCredentials, error) {
	data, err := ioutil.ReadFile(token)
	if err != nil {
		return jwt{}, err
	}

	if len(data) == 0 {
		return jwt{}, fmt.Errorf("token can not be empty")
	}

	return jwt{string(data)}, nil
}

func (j jwt) GetRequestMetadata(ctx context.Context, uri ...string) (map[string]string, error) {
	return map[string]string{
		"authorization": j.token,
	}, nil
}

func (j jwt) RequireTransportSecurity() bool {
	return true
}
