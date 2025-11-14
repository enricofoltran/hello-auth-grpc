package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"log"
	"os"
	"time"

	pb "github.com/enricofoltran/hello-auth-grpc/auth"
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
	serverAddr := flag.String("server-addr", "127.0.0.1:20000", "remote auth server address")
	tlsCrt := flag.String("tls-crt", config.WithConfigDir("client.pem"), "client certificate file")
	tlsKey := flag.String("tls-key", config.WithConfigDir("client-key.pem"), "client private key file")
	caCrt := flag.String("ca-crt", config.WithConfigDir("ca.pem"), "CA certificate file")
	jwtToken := flag.String("jwt-token", config.WithConfigDir(".token"), "the jwt auth token file")
	flag.Parse()

	logger := log.New(os.Stderr, "auth-client: ", log.LstdFlags)

	// Get credentials from environment variables (more secure than CLI flags)
	username := os.Getenv("AUTH_USERNAME")
	password := os.Getenv("AUTH_PASSWORD")

	if username == "" || password == "" {
		logger.Fatalln("please provide AUTH_USERNAME and AUTH_PASSWORD environment variables")
	}

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

	// Connect with dial options
	conn, err := grpc.NewClient(
		*serverAddr,
		grpc.WithTransportCredentials(tlsCreds),
	)
	if err != nil {
		logger.Fatalf("could not create client: %v", err)
	}
	defer conn.Close()

	clt := pb.NewAuthClient(conn)

	// Use context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), RequestTimeout)
	defer cancel()

	req := &pb.Request{Username: username, Password: password}
	res, err := clt.Login(ctx, req)
	if err != nil {
		logger.Fatalf("could not login: %v", err)
	}

	// Save token with restricted permissions (0600 = owner read/write only)
	err = os.WriteFile(*jwtToken, []byte(res.Token), 0600)
	if err != nil {
		logger.Fatalf("could not save auth token to disk: %v", err)
	}

	logger.Println("login succeeded!")
}
