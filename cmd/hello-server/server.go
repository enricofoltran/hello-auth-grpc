package main

import (
	"context"
	"crypto/rsa"
	"fmt"
	"os"

	pb "github.com/enricofoltran/hello-auth-grpc/hello"
	"github.com/golang-jwt/jwt/v5"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

const (
	// ExpectedAudience is the expected audience claim for JWT tokens
	ExpectedAudience = "hello.service"
	// ExpectedIssuer is the expected issuer claim for JWT tokens
	ExpectedIssuer = "auth.service"
)

// server implements the Greeter service with JWT authentication.
type server struct {
	pb.UnimplementedGreeterServer
	jwtKey *rsa.PublicKey
}

// claims represents the JWT claims structure with validation.
type claims struct {
	jwt.RegisteredClaims
}

// validateJwtToken validates a JWT token with comprehensive claims checking.
func validateJwtToken(tokenString string, key *rsa.PublicKey) (*jwt.Token, *claims, error) {
	// Parse and validate the token
	jwtToken, err := jwt.ParseWithClaims(tokenString, &claims{}, func(t *jwt.Token) (interface{}, error) {
		// Verify signing method
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return key, nil
	})

	if err != nil {
		return nil, nil, fmt.Errorf("token parsing failed: %w", err)
	}

	// Extract and validate claims
	claims, ok := jwtToken.Claims.(*claims)
	if !ok || !jwtToken.Valid {
		return nil, nil, fmt.Errorf("invalid token claims")
	}

	// Validate audience
	audiences, err := claims.GetAudience()
	if err != nil {
		return nil, nil, fmt.Errorf("invalid audience claim: %w", err)
	}
	validAudience := false
	for _, aud := range audiences {
		if aud == ExpectedAudience {
			validAudience = true
			break
		}
	}
	if !validAudience {
		return nil, nil, fmt.Errorf("invalid audience: expected %s", ExpectedAudience)
	}

	// Validate issuer
	issuer, err := claims.GetIssuer()
	if err != nil {
		return nil, nil, fmt.Errorf("invalid issuer claim: %w", err)
	}
	if issuer != ExpectedIssuer {
		return nil, nil, fmt.Errorf("invalid issuer: expected %s, got %s", ExpectedIssuer, issuer)
	}

	// Validate expiration (jwt library does this automatically, but we check explicitly)
	if exp, err := claims.GetExpirationTime(); err != nil || exp == nil {
		return nil, nil, fmt.Errorf("invalid expiration claim")
	}

	// Validate not before (jwt library does this automatically, but we check explicitly)
	if nbf, err := claims.GetNotBefore(); err != nil || nbf == nil {
		return nil, nil, fmt.Errorf("invalid not-before claim")
	}

	return jwtToken, claims, nil
}

// NewHelloServer creates a new hello server instance.
func NewHelloServer(jwtKeyPath string) (*server, error) {
	rawJwtKey, err := os.ReadFile(jwtKeyPath)
	if err != nil {
		return nil, fmt.Errorf("could not load jwt public key from file: %w", err)
	}

	parsedJwtKey, err := jwt.ParseRSAPublicKeyFromPEM(rawJwtKey)
	if err != nil {
		return nil, fmt.Errorf("could not parse jwt public key: %w", err)
	}

	return &server{jwtKey: parsedJwtKey}, nil
}

// SayHello implements the Greeter service with JWT authentication.
func (s *server) SayHello(ctx context.Context, r *pb.Request) (*pb.Response, error) {
	// Extract metadata from context
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "missing authentication metadata")
	}

	// Get authorization token
	jwtTokens, ok := md["authorization"]
	if !ok || len(jwtTokens) == 0 {
		return nil, status.Error(codes.Unauthenticated, "missing authorization token")
	}

	// Validate the JWT token
	_, claims, err := validateJwtToken(jwtTokens[0], s.jwtKey)
	if err != nil {
		// Don't leak validation error details to client
		return nil, status.Error(codes.Unauthenticated, "invalid authentication token")
	}

	// Extract subject (username) from claims
	subject, err := claims.GetSubject()
	if err != nil || subject == "" {
		return nil, status.Error(codes.Unauthenticated, "invalid token subject")
	}

	return &pb.Response{Message: "Hello, " + subject + "!"}, nil
}
