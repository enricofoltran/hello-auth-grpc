package main

import (
	"crypto/rsa"
	"fmt"
	"io/ioutil"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	pb "github.com/enricofoltran/hello-auth-grpc/auth"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
)

type server struct {
	jwtKey   *rsa.PrivateKey
	username string
	password string
}

// NewAuthServer return an new auth server instance
func NewAuthServer(jwtKey, username, password string) (*server, error) {
	rawJwtKey, err := ioutil.ReadFile(jwtKey)
	if err != nil {
		return nil, fmt.Errorf("could not load jwt private key from file: %v", err)
	}

	parsedJwtKey, err := jwt.ParseRSAPrivateKeyFromPEM(rawJwtKey)
	if err != nil {
		return nil, fmt.Errorf("could not parse jwt private key: %v", err)
	}

	return &server{
		jwtKey:   parsedJwtKey,
		username: username,
		password: password,
	}, nil
}

func (s *server) Login(ctx context.Context, r *pb.Request) (*pb.Response, error) {
	if r.Username != s.username || r.Password != s.password {
		return nil, grpc.Errorf(codes.PermissionDenied, "invalid username or password")
	}

	now := time.Now()
	exp := now.Add(time.Hour * 72)

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"sub": r.Username,
		"aud": "hello.service",
		"iss": "auth.service",
		"exp": exp.Unix(),
		"iat": now.Unix(),
		"nbf": now.Unix(),
	})

	tokenStr, err := token.SignedString(s.jwtKey)
	if err != nil {
		return nil, grpc.Errorf(codes.Internal, err.Error())
	}

	return &pb.Response{Token: tokenStr}, nil
}
