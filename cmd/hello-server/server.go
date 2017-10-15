package main

import (
	"crypto/rsa"
	"fmt"
	"io/ioutil"

	jwt "github.com/dgrijalva/jwt-go"
	pb "github.com/enricofoltran/hello-auth-grpc/hello"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
)

type server struct {
	jwtKey *rsa.PublicKey
}

type claims struct {
	jwt.StandardClaims
}

func validateJwtToken(token string, key *rsa.PublicKey) (*jwt.Token, *claims, error) {
	jwtToken, err := jwt.ParseWithClaims(token, &claims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("valid auth token required")
		}
		return key, nil
	})

	if claims, ok := jwtToken.Claims.(*claims); ok && jwtToken.Valid {
		return jwtToken, claims, nil
	}

	return nil, nil, err
}

// NewHelloServer return an new hello server instance
func NewHelloServer(jwtKey string) (*server, error) {
	rawJwtKey, err := ioutil.ReadFile(jwtKey)
	if err != nil {
		return nil, fmt.Errorf("could not load jwt public key from file: %v", err)
	}

	parsedJwtKey, err := jwt.ParseRSAPublicKeyFromPEM(rawJwtKey)
	if err != nil {
		return nil, fmt.Errorf("could not parse jwt public key: %v", err)
	}

	return &server{jwtKey: parsedJwtKey}, nil
}

func (s *server) SayHello(ctx context.Context, r *pb.Request) (*pb.Response, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, grpc.Errorf(codes.Unauthenticated, "valid auth token required")
	}

	jwtToken, ok := md["authorization"]
	if !ok {
		return nil, grpc.Errorf(codes.Unauthenticated, "valid auth token required")
	}

	_, claims, err := validateJwtToken(jwtToken[0], s.jwtKey)
	if err != nil {
		return nil, grpc.Errorf(codes.Unauthenticated, "valid auth token required: %v", err)
	}

	return &pb.Response{Message: "Hello, " + claims.Subject + "!"}, nil
}
