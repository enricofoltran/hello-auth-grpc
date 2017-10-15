package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"io/ioutil"
	"log"
	"net"
	"os"
	"path/filepath"

	pb "github.com/enricofoltran/hello-auth-grpc/auth"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

func withConfigDir(path string) string {
	return filepath.Join(os.Getenv("HOME"), ".hello", path)
}

func main() {
	listenAddr := flag.String("listen-addr", "127.0.0.1:20000", "auth server listen address")
	jwtKey := flag.String("jwt-key", withConfigDir("jwt-key.pem"), "the private key to use for signing JWT tokens")
	tlsCrt := flag.String("tls-crt", withConfigDir("auth.pem"), "auth server certificate file")
	tlsKey := flag.String("tls-key", withConfigDir("auth-key.pem"), "auth server private key file")
	caCrt := flag.String("ca-crt", withConfigDir("ca.pem"), "CA certificate file")
	username := flag.String("username", "", "username")
	password := flag.String("password", "", "password")
	flag.Parse()

	logger := log.New(os.Stderr, "auth: ", log.LstdFlags)
	logger.Printf("server is starting...")

	if *username == "" || *password == "" {
		logger.Fatalln("please provide an username and a password")
	}

	crt, err := tls.LoadX509KeyPair(*tlsCrt, *tlsKey)
	if err != nil {
		logger.Fatalf("could not load client key pair from file: %v", err)
	}

	rawCaCrt, err := ioutil.ReadFile(*caCrt)
	if err != nil {
		logger.Fatalf("could not load CA certificate from file: %v", err)
	}

	caCrtPool := x509.NewCertPool()
	if ok := caCrtPool.AppendCertsFromPEM(rawCaCrt); !ok {
		logger.Fatalf("could not append CA certificate to cert pool: %v", err)
	}

	tlsCreds := credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{crt},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    caCrtPool,
	})

	ln, err := net.Listen("tcp", *listenAddr)
	if err != nil {
		logger.Fatalf("could not listen: %v", err)
	}

	grpcServer := grpc.NewServer(grpc.Creds(tlsCreds))

	authServer, err := NewAuthServer(*jwtKey, *username, *password)
	if err != nil {
		logger.Fatalf("%v", err)
	}

	pb.RegisterAuthServer(grpcServer, authServer)

	logger.Printf("server is listening on port %s...", *listenAddr)
	grpcServer.Serve(ln)
}
