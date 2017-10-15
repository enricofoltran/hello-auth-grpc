CONFIG_PATH=${HOME}/.hello/

all: init gencert build

init:
	mkdir -p ${CONFIG_PATH}

build:
	dep ensure
	protoc --go_out=plugins=grpc:. hello/hello.proto
	protoc --go_out=plugins=grpc:. auth/auth.proto
	mkdir -p bin
	go build -a --ldflags '-extldflags "-static"' -tags netgo -installsuffix netgo -o bin/auth-client ./cmd/auth-client
	go build -a --ldflags '-extldflags "-static"' -tags netgo -installsuffix netgo -o bin/auth-server ./cmd/auth-server
	go build -a --ldflags '-extldflags "-static"' -tags netgo -installsuffix netgo -o bin/hello-client ./cmd/hello-client
	go build -a --ldflags '-extldflags "-static"' -tags netgo -installsuffix netgo -o bin/hello-server ./cmd/hello-server

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
