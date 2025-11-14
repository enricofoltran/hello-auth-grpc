# Configuration directory for certificates and keys
CONFIG_PATH=${HOME}/.hello/

# Default target
all: init gencert build

# Create configuration directory
init:
	mkdir -p ${CONFIG_PATH}

# Build all binaries and generate protobuf code
build:
	go mod download
	protoc --go_out=. --go_opt=paths=source_relative \
		--go-grpc_out=. --go-grpc_opt=paths=source_relative \
		hello/hello.proto
	protoc --go_out=. --go_opt=paths=source_relative \
		--go-grpc_out=. --go-grpc_opt=paths=source_relative \
		auth/auth.proto
	mkdir -p bin
	go build -o bin/auth-client ./cmd/auth-client
	go build -o bin/auth-server ./cmd/auth-server
	go build -o bin/hello-client ./cmd/hello-client
	go build -o bin/hello-server ./cmd/hello-server

# Generate all certificates and keys using CFSSL
gencert:
	cfssl gencert \
		-initca certs/ca-csr.json | cfssljson -bare ca

	cfssl gencert \
		-ca=ca.pem \
		-ca-key=ca-key.pem \
		-config=certs/ca-config.json \
		-profile=server \
		certs/hello-csr.json | cfssljson -bare hello

	cfssl gencert \
		-ca=ca.pem \
		-ca-key=ca-key.pem \
		-config=certs/ca-config.json \
		-profile=server \
		certs/auth-csr.json | cfssljson -bare auth

	cfssl gencert \
		-ca=ca.pem \
		-ca-key=ca-key.pem \
		-config=certs/ca-config.json \
		-profile=client \
		certs/client-csr.json | cfssljson -bare client

	cfssl gencert \
		-ca=ca.pem \
		-ca-key=ca-key.pem \
		-config=certs/ca-config.json \
		-profile=signing \
		certs/jwt-csr.json | cfssljson -bare jwt

	mv *.pem *.csr ${CONFIG_PATH}

# Clean build artifacts
clean:
	rm -rf bin/
	rm -f hello/hello_grpc.pb.go hello/hello.pb.go
	rm -f auth/auth_grpc.pb.go auth/auth.pb.go

# Clean everything including certificates
clean-all: clean
	rm -rf ${CONFIG_PATH}

# Run tests
test:
	go test -v -race -coverprofile=coverage.out ./...

# Show test coverage
coverage: test
	go tool cover -html=coverage.out

# Install protobuf compiler plugins
install-tools:
	go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
	go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest

.PHONY: all init build gencert clean clean-all test coverage install-tools
