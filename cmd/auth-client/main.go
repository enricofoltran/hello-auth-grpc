package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"

	pb "github.com/enricofoltran/hello-auth-grpc/auth"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

func withConfigDir(path string) string {
	return filepath.Join(os.Getenv("HOME"), ".hello", path)
}

func main() {
	serverAddr := flag.String("server-addr", "127.0.0.1:20000", "remote auth server address")
	tlsCrt := flag.String("tls-crt", withConfigDir("client.pem"), "client certificate file")
	tlsKey := flag.String("tls-key", withConfigDir("client-key.pem"), "client private key file")
	caCrt := flag.String("ca-crt", withConfigDir("ca.pem"), "CA certificate file")
	jwtToken := flag.String("jwt-token", withConfigDir(".token"), "the jwt auth token file")
	username := flag.String("username", "", "username")
	password := flag.String("password", "", "password")
	flag.Parse()

	logger := log.New(os.Stderr, "auth: ", log.LstdFlags)

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
		RootCAs:      caCrtPool,
	})

	conn, err := grpc.Dial(
		*serverAddr,
		grpc.WithTransportCredentials(tlsCreds),
	)
	if err != nil {
		logger.Fatalf("could not connect to remote server: %v", err)
	}
	defer conn.Close()

	clt := pb.NewAuthClient(conn)

	req := &pb.Request{Username: *username, Password: *password}
	res, err := clt.Login(context.Background(), req)
	if err != nil {
		logger.Fatalf("could not login: %v", err)
	}

	err = ioutil.WriteFile(*jwtToken, []byte(res.Token), 0600)
	if err != nil {
		logger.Fatalf("could not save auth token to disk: %v", err)
	}

	logger.Println("login succeeded!")
}
