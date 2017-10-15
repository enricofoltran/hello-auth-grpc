package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"

	"github.com/enricofoltran/hello-auth-grpc/credentials/jwt"
	pb "github.com/enricofoltran/hello-auth-grpc/hello"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

func withConfigDir(path string) string {
	return filepath.Join(os.Getenv("HOME"), ".hello", path)
}

func main() {
	serverAddr := flag.String("server-addr", "127.0.0.1:10000", "remote hello server address")
	tlsCrt := flag.String("tls-crt", withConfigDir("client.pem"), "client certificate file")
	tlsKey := flag.String("tls-key", withConfigDir("client-key.pem"), "client private key file")
	caCrt := flag.String("ca-crt", withConfigDir("ca.pem"), "CA certificate file")
	jwtToken := flag.String("jwt-token", withConfigDir(".token"), "the jwt auth token file")
	flag.Parse()

	logger := log.New(os.Stderr, "hello: ", log.LstdFlags)

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
		RootCAs:      caCrtPool,
	})

	jwtCreds, err := jwt.NewFromTokenFile(*jwtToken)
	if err != nil {
		logger.Fatalf("could not load jwt token from file: %v", err)
	}

	conn, err := grpc.Dial(
		*serverAddr,
		grpc.WithTransportCredentials(tlsCreds),
		grpc.WithPerRPCCredentials(jwtCreds),
	)
	if err != nil {
		logger.Fatalf("could not connect to remote server: %v", err)
	}
	defer conn.Close()

	clt := pb.NewGreeterClient(conn)

	req := &pb.Request{}
	res, err := clt.SayHello(context.Background(), req)
	if err != nil {
		logger.Fatalf("could not say hello: %v", err)
	}

	logger.Printf("remote server say: %s", res.Message)
}
