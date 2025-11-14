package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	pb "github.com/enricofoltran/hello-auth-grpc/hello"
	"github.com/enricofoltran/hello-auth-grpc/pkg/config"
	"github.com/enricofoltran/hello-auth-grpc/pkg/logging"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
)

func main() {
	// Define flags
	listenAddr := flag.String("listen-addr", "127.0.0.1:10000", "hello server listen address")
	jwtKey := flag.String("jwt-key", config.WithConfigDir("jwt.pem"), "the public key to use for validating JWT tokens")
	tlsCrt := flag.String("tls-crt", config.WithConfigDir("hello.pem"), "hello server certificate file")
	tlsKey := flag.String("tls-key", config.WithConfigDir("hello-key.pem"), "hello server private key file")
	caCrt := flag.String("ca-crt", config.WithConfigDir("ca.pem"), "CA certificate file")
	flag.Parse()

	logger := log.New(os.Stderr, "hello: ", log.LstdFlags)
	logger.Printf("server is starting...")

	// Load TLS certificate and key
	crt, err := tls.LoadX509KeyPair(*tlsCrt, *tlsKey)
	if err != nil {
		logger.Fatalf("could not load server key pair from file: %v", err)
	}

	// Load CA certificate
	rawCaCrt, err := os.ReadFile(*caCrt)
	if err != nil {
		logger.Fatalf("could not load CA certificate from file: %v", err)
	}

	caCrtPool := x509.NewCertPool()
	if ok := caCrtPool.AppendCertsFromPEM(rawCaCrt); !ok {
		// Fixed: Don't reference wrong error variable
		logger.Fatalf("could not append CA certificate to cert pool")
	}

	// Hardened TLS configuration
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{crt},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    caCrtPool,
		MinVersion:   tls.VersionTLS12, // Enforce minimum TLS 1.2
		CipherSuites: []uint16{
			// Strong cipher suites only
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		},
		PreferServerCipherSuites: true,
	}

	tlsCreds := credentials.NewTLS(tlsConfig)

	// Create listener
	ln, err := net.Listen("tcp", *listenAddr)
	if err != nil {
		logger.Fatalf("could not listen: %v", err)
	}

	// Create gRPC server with interceptors for logging and panic recovery
	grpcServer := grpc.NewServer(
		grpc.Creds(tlsCreds),
		grpc.ChainUnaryInterceptor(
			logging.PanicRecoveryInterceptor(logger),
			logging.UnaryServerInterceptor(logger),
		),
	)

	// Create and register hello server
	helloServer, err := NewHelloServer(*jwtKey)
	if err != nil {
		logger.Fatalf("%v", err)
	}

	pb.RegisterGreeterServer(grpcServer, helloServer)

	// Register health check service
	healthServer := health.NewServer()
	healthpb.RegisterHealthServer(grpcServer, healthServer)
	healthServer.SetServingStatus("hello.Greeter", healthpb.HealthCheckResponse_SERVING)

	// Set up graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sigChan
		logger.Println("shutting down gracefully...")
		grpcServer.GracefulStop()
	}()

	logger.Printf("server is listening on %s...", *listenAddr)
	if err := grpcServer.Serve(ln); err != nil {
		logger.Fatalf("failed to serve: %v", err)
	}
}
