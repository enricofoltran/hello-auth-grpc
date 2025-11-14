package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"log"
	"os"
	"time"

	"github.com/enricofoltran/hello-auth-grpc/credentials/jwt"
	pb "github.com/enricofoltran/hello-auth-grpc/hello"
	"github.com/enricofoltran/hello-auth-grpc/pkg/config"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

const (
	// RequestTimeout is the maximum time to wait for a request
	RequestTimeout = 10 * time.Second
)

func main() {
	// Define flags
	serverAddr := flag.String("server-addr", "127.0.0.1:10000", "remote hello server address")
	tlsCrt := flag.String("tls-crt", config.WithConfigDir("client.pem"), "client certificate file")
	tlsKey := flag.String("tls-key", config.WithConfigDir("client-key.pem"), "client private key file")
	caCrt := flag.String("ca-crt", config.WithConfigDir("ca.pem"), "CA certificate file")
	jwtToken := flag.String("jwt-token", config.WithConfigDir(".token"), "the jwt auth token file")
	flag.Parse()

	logger := log.New(os.Stderr, "hello-client: ", log.LstdFlags)

	// Load TLS certificate and key
	crt, err := tls.LoadX509KeyPair(*tlsCrt, *tlsKey)
	if err != nil {
		logger.Fatalf("could not load client key pair from file: %v", err)
	}

	// Load CA certificate
	rawCaCrt, err := os.ReadFile(*caCrt)
	if err != nil {
		logger.Fatalf("could not load CA certificate from file: %v", err)
	}

	caCrtPool := x509.NewCertPool()
	if ok := caCrtPool.AppendCertsFromPEM(rawCaCrt); !ok {
		logger.Fatalf("could not append CA certificate to cert pool")
	}

	// Hardened TLS configuration
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{crt},
		RootCAs:      caCrtPool,
		MinVersion:   tls.VersionTLS12,
	}

	tlsCreds := credentials.NewTLS(tlsConfig)

	// Load JWT credentials
	jwtCreds, err := jwt.NewFromTokenFile(*jwtToken)
	if err != nil {
		logger.Fatalf("could not load jwt token from file: %v", err)
	}

	// Connect with dial options
	conn, err := grpc.NewClient(
		*serverAddr,
		grpc.WithTransportCredentials(tlsCreds),
		grpc.WithPerRPCCredentials(jwtCreds),
	)
	if err != nil {
		logger.Fatalf("could not create client: %v", err)
	}
	defer conn.Close()

	clt := pb.NewGreeterClient(conn)

	// Use context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), RequestTimeout)
	defer cancel()

	req := &pb.Request{}
	res, err := clt.SayHello(ctx, req)
	if err != nil {
		logger.Fatalf("could not say hello: %v", err)
	}

	logger.Printf("remote server says: %s", res.Message)
}
