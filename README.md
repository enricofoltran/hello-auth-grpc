# hello-auth-grpc

A secure gRPC microservices demonstration implementing JWT-based authentication with mutual TLS encryption.

## Overview

This project demonstrates production-ready security patterns for gRPC services in Go, including:

- **JWT Authentication**: RSA-2048 signed tokens with comprehensive claims validation
- **Mutual TLS (mTLS)**: Certificate-based encryption and authentication
- **Rate Limiting**: Protection against brute force attacks
- **Password Security**: bcrypt password hashing
- **Input Validation**: Comprehensive validation of all user inputs
- **Graceful Shutdown**: Proper signal handling for clean shutdowns
- **Request Logging**: Structured logging with interceptors
- **Health Checks**: Standard gRPC health checking protocol
- **Panic Recovery**: Middleware to prevent crashes

## Architecture

The project consists of two independent microservices:

### 1. Auth Service (Port 20000)

Authenticates users and issues JWT tokens.

- **Endpoint**: `Auth.Login`
- **Input**: Username and password
- **Output**: Signed JWT token (1-hour validity)
- **Security Features**:
  - bcrypt password hashing
  - Rate limiting (1 request per 2 seconds per IP)
  - Input validation (username: 1-64 chars, password: 8-128 chars)
  - Constant-time comparison to prevent timing attacks

### 2. Hello Service (Port 10000)

Provides greeting functionality secured by JWT authentication.

- **Endpoint**: `Greeter.SayHello`
- **Input**: Empty (username extracted from JWT)
- **Output**: Personalized greeting
- **Security Features**:
  - JWT signature verification (RSA)
  - Comprehensive claims validation (aud, iss, exp, nbf)
  - Token expiration checking

## Prerequisites

- **Go**: 1.21 or later
- **protoc**: Protocol Buffer compiler (optional, for regenerating proto files)
- **cfssl**: CloudFlare PKI toolkit for certificate generation

### Installing Prerequisites

```bash
# Install Go (if not already installed)
# See: https://golang.org/doc/install

# Install cfssl
go install github.com/cloudflare/cfssl/cmd/...@latest

# Install protoc (optional)
# See: https://grpc.io/docs/protoc-installation/

# Install protoc plugins (optional)
make install-tools
```

## Quick Start

### 1. Setup

Clone and initialize the project:

```bash
git clone <repository-url>
cd hello-auth-grpc
make init      # Create ~/.hello/ directory
make gencert   # Generate certificates and keys
```

### 2. Set Credentials

**IMPORTANT**: Use environment variables for credentials (not command-line flags):

```bash
export AUTH_USERNAME="admin"
export AUTH_PASSWORD="secureP@ssw0rd123"  # Must be 8-128 characters
```

### 3. Build

```bash
make build
```

This will:
- Download dependencies
- Generate protobuf code (if protoc is installed)
- Build all binaries to `bin/` directory

### 4. Run Services

**Terminal 1 - Start Auth Service:**
```bash
export AUTH_USERNAME="admin"
export AUTH_PASSWORD="secureP@ssw0rd123"
./bin/auth-server
```

**Terminal 2 - Start Hello Service:**
```bash
./bin/hello-server
```

### 5. Test the Services

**Terminal 3 - Authenticate and Get Token:**
```bash
export AUTH_USERNAME="admin"
export AUTH_PASSWORD="secureP@ssw0rd123"
./bin/auth-client
```

**Terminal 4 - Call Authenticated Service:**
```bash
./bin/hello-client
```

Expected output:
```
hello-client: 2025/11/14 12:00:00 remote server says: Hello, admin!
```

## Configuration

### Environment Variables

| Variable | Description | Required | Default |
|----------|-------------|----------|---------|
| `AUTH_USERNAME` | Username for authentication | Yes | - |
| `AUTH_PASSWORD` | Password (8-128 characters) | Yes | - |
| `HELLO_CONFIG_DIR` | Configuration directory | No | `~/.hello` |

### Command-Line Flags

#### Auth Server
```bash
./bin/auth-server \
  --listen-addr 127.0.0.1:20000 \
  --jwt-key ~/.hello/jwt-key.pem \
  --tls-crt ~/.hello/auth.pem \
  --tls-key ~/.hello/auth-key.pem \
  --ca-crt ~/.hello/ca.pem
```

#### Hello Server
```bash
./bin/hello-server \
  --listen-addr 127.0.0.1:10000 \
  --jwt-key ~/.hello/jwt.pem \
  --tls-crt ~/.hello/hello.pem \
  --tls-key ~/.hello/hello-key.pem \
  --ca-crt ~/.hello/ca.pem
```

#### Auth Client
```bash
./bin/auth-client \
  --server-addr 127.0.0.1:20000 \
  --jwt-token ~/.hello/.token \
  --tls-crt ~/.hello/client.pem \
  --tls-key ~/.hello/client-key.pem \
  --ca-crt ~/.hello/ca.pem
```

#### Hello Client
```bash
./bin/hello-client \
  --server-addr 127.0.0.1:10000 \
  --jwt-token ~/.hello/.token \
  --tls-crt ~/.hello/client.pem \
  --tls-key ~/.hello/client-key.pem \
  --ca-crt ~/.hello/ca.pem
```

## Security Features

### TLS Configuration

- **Minimum Version**: TLS 1.2
- **Cipher Suites**: Only strong ECDHE ciphers with AES-GCM
- **Certificate Validation**: Mutual TLS with CA verification
- **Key Size**: RSA 2048-bit (consider upgrading to 4096-bit for production)

### JWT Configuration

- **Algorithm**: RS256 (RSA with SHA-256)
- **Key Size**: 2048-bit RSA
- **Token Lifetime**: 1 hour
- **Claims Validated**:
  - `sub` (Subject): Username
  - `aud` (Audience): "hello.service"
  - `iss` (Issuer): "auth.service"
  - `exp` (Expiration): Automatic validation
  - `nbf` (Not Before): Automatic validation
  - `iat` (Issued At): Timestamp

### Rate Limiting

- **Rate**: 0.5 requests/second (1 request every 2 seconds)
- **Burst**: 3 requests
- **Scope**: Per client IP address
- **Response**: HTTP 429 (Resource Exhausted)

### Password Requirements

- **Minimum Length**: 8 characters
- **Maximum Length**: 128 characters
- **Storage**: bcrypt hashed (cost factor: 10)
- **Comparison**: Constant-time to prevent timing attacks

## Development

### Project Structure

```
hello-auth-grpc/
├── auth/                    # Auth service protobuf definitions
│   ├── auth.proto
│   └── auth.pb.go          # Generated code
├── hello/                   # Hello service protobuf definitions
│   ├── hello.proto
│   └── hello.pb.go         # Generated code
├── cmd/                     # Application entry points
│   ├── auth-server/        # Auth server implementation
│   ├── auth-client/        # Auth client implementation
│   ├── hello-server/       # Hello server implementation
│   └── hello-client/       # Hello client implementation
├── pkg/                     # Shared packages
│   ├── config/             # Configuration utilities
│   └── logging/            # Logging and interceptors
├── credentials/            # Custom credential providers
│   └── jwt/                # JWT credential implementation
├── certs/                  # Certificate configuration files
├── Makefile               # Build automation
└── README.md              # This file
```

### Makefile Targets

```bash
make all          # Initialize, generate certificates, and build
make init         # Create configuration directory
make build        # Build all binaries
make gencert      # Generate certificates and keys
make clean        # Remove binaries and generated code
make clean-all    # Remove everything including certificates
make test         # Run tests with race detection and coverage
make coverage     # Generate and view coverage report
make install-tools # Install protobuf compiler plugins
```

### Running Tests

```bash
# Run all tests
make test

# Run tests with coverage
make coverage

# Run specific package tests
go test -v ./pkg/config/
go test -v ./cmd/auth-server/
```

### Adding New Services

1. Define protobuf service in `<service>/<service>.proto`
2. Generate Go code: `protoc --go_out=. --go-grpc_out=. <service>/<service>.proto`
3. Implement server in `cmd/<service>-server/`
4. Implement client in `cmd/<service>-client/`
5. Add to Makefile build targets

## Health Checks

Both services implement the standard gRPC health checking protocol:

```bash
# Using grpcurl (install: go install github.com/fullstorydev/grpcurl/cmd/grpcurl@latest)
grpcurl -plaintext localhost:20000 grpc.health.v1.Health/Check
grpcurl -plaintext localhost:10000 grpc.health.v1.Health/Check
```

Expected response:
```json
{
  "status": "SERVING"
}
```

## Logging

All services log to stderr with structured format:

```
auth-server: 2025/11/14 12:00:00 server is starting...
auth-server: 2025/11/14 12:00:01 method=/auth.Auth/Login client=127.0.0.1:54321 code=OK duration=45ms
```

## Graceful Shutdown

Services handle `SIGTERM` and `SIGINT` signals:

```bash
# Send SIGTERM
kill -TERM <pid>

# Or Ctrl+C (SIGINT)
```

Services will:
1. Stop accepting new connections
2. Wait for active requests to complete
3. Clean up resources
4. Exit

## Troubleshooting

### Common Issues

**1. "could not load CA certificate"**
- Run `make gencert` to generate certificates
- Check that `~/.hello/` directory exists
- Verify certificate files have correct permissions

**2. "please provide AUTH_USERNAME and AUTH_PASSWORD"**
- Set environment variables before running servers/clients
- Don't use command-line flags for credentials (security risk)

**3. "could not connect to remote server"**
- Ensure server is running
- Check firewall rules
- Verify server address and port

**4. "invalid credentials"**
- Verify AUTH_USERNAME and AUTH_PASSWORD match server settings
- Check password meets minimum length requirement (8 chars)

**5. "too many login attempts"**
- Rate limiting is active
- Wait 2 seconds between attempts
- Check for multiple clients from same IP

**6. "invalid authentication token"**
- Token may be expired (1-hour lifetime)
- Run auth-client to get new token
- Verify token file exists at `~/.hello/.token`

### Debugging

Enable verbose logging:

```bash
# Set Go's GODEBUG
export GODEBUG=http2debug=2

# Run with race detector
go run -race ./cmd/auth-server/
```

## Security Considerations

### Production Deployment

For production use, consider these additional hardening measures:

1. **Certificates**
   - Use 4096-bit RSA keys or ECDSA P-384
   - Implement certificate rotation
   - Use short-lived certificates (90 days or less)
   - Store private keys in hardware security modules (HSM)

2. **Authentication**
   - Implement multi-factor authentication (MFA)
   - Add account lockout after N failed attempts
   - Use external identity providers (OAuth2, OIDC)
   - Implement refresh token mechanism

3. **Authorization**
   - Add role-based access control (RBAC)
   - Implement fine-grained permissions
   - Audit all access attempts

4. **Network**
   - Deploy behind load balancer
   - Use firewall rules to restrict access
   - Enable DDoS protection
   - Implement network segmentation

5. **Monitoring**
   - Add Prometheus metrics
   - Set up alerting (PagerDuty, Opsgenie)
   - Enable distributed tracing (Jaeger, Zipkin)
   - Log aggregation (ELK, Loki)

6. **Token Management**
   - Implement token revocation/blacklisting
   - Reduce token lifetime (15-30 minutes)
   - Add refresh token rotation
   - Store tokens securely (encrypted)

## API Documentation

### Auth Service

#### Login

Authenticates a user and returns a JWT token.

**Request:**
```protobuf
message Request {
  string username = 1;  // 1-64 characters
  string password = 2;  // 8-128 characters
}
```

**Response:**
```protobuf
message Response {
  string token = 1;  // JWT token (1-hour validity)
}
```

**Errors:**
- `InvalidArgument`: Invalid username or password format
- `PermissionDenied`: Invalid credentials
- `ResourceExhausted`: Rate limit exceeded
- `Internal`: Server error

### Hello Service

#### SayHello

Returns a personalized greeting for the authenticated user.

**Request:**
```protobuf
message Request {}  // Empty - username from JWT
```

**Response:**
```protobuf
message Response {
  string message = 1;  // Greeting message
}
```

**Errors:**
- `Unauthenticated`: Missing, invalid, or expired token
- `Internal`: Server error

**Authentication:**
Include JWT token in request metadata:
```
authorization: <jwt-token>
```

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Run tests (`make test`)
5. Commit your changes (`git commit -m 'Add amazing feature'`)
6. Push to the branch (`git push origin feature/amazing-feature`)
7. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Built with [gRPC](https://grpc.io/)
- JWT handling with [golang-jwt](https://github.com/golang-jwt/jwt)
- Certificate generation with [CFSSL](https://github.com/cloudflare/cfssl)

## Support

For issues, questions, or contributions, please open an issue on GitHub.
