package main

import (
	"context"
	"crypto/rsa"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	pb "github.com/enricofoltran/hello-auth-grpc/auth"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/time/rate"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

const (
	// MaxUsernameLength is the maximum allowed username length
	MaxUsernameLength = 64
	// MaxPasswordLength is the maximum allowed password length
	MaxPasswordLength = 128
	// MinPasswordLength is the minimum required password length
	MinPasswordLength = 8
	// TokenExpiration is the JWT token validity duration (1 hour)
	TokenExpiration = time.Hour
	// RateLimitBurst allows burst of login attempts
	RateLimitBurst = 3
	// RateLimitPerSecond limits login attempts per second per IP
	RateLimitPerSecond = 0.5 // 1 request every 2 seconds
)

// server implements the Auth service with security enhancements.
type server struct {
	jwtKey         *rsa.PrivateKey
	passwordHash   []byte // bcrypt hash of the password
	username       string
	rateLimiters   map[string]*rate.Limiter
	rateLimitersMu sync.RWMutex
}

// NewAuthServer creates a new auth server instance with bcrypt password hashing.
// The password parameter should be the plaintext password which will be hashed.
func NewAuthServer(jwtKeyPath, username, password string) (*server, error) {
	// Validate inputs
	if err := validateUsername(username); err != nil {
		return nil, fmt.Errorf("invalid username: %w", err)
	}

	if err := validatePassword(password); err != nil {
		return nil, fmt.Errorf("invalid password: %w", err)
	}

	// Load JWT private key
	rawJwtKey, err := os.ReadFile(jwtKeyPath)
	if err != nil {
		return nil, fmt.Errorf("could not load jwt private key from file: %w", err)
	}

	parsedJwtKey, err := jwt.ParseRSAPrivateKeyFromPEM(rawJwtKey)
	if err != nil {
		return nil, fmt.Errorf("could not parse jwt private key: %w", err)
	}

	// Hash the password using bcrypt
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("could not hash password: %w", err)
	}

	return &server{
		jwtKey:       parsedJwtKey,
		username:     username,
		passwordHash: passwordHash,
		rateLimiters: make(map[string]*rate.Limiter),
	}, nil
}

// validateUsername checks if the username meets requirements.
func validateUsername(username string) error {
	username = strings.TrimSpace(username)
	if username == "" {
		return fmt.Errorf("username cannot be empty")
	}
	if len(username) > MaxUsernameLength {
		return fmt.Errorf("username exceeds maximum length of %d", MaxUsernameLength)
	}
	return nil
}

// validatePassword checks if the password meets requirements.
func validatePassword(password string) error {
	if len(password) < MinPasswordLength {
		return fmt.Errorf("password must be at least %d characters", MinPasswordLength)
	}
	if len(password) > MaxPasswordLength {
		return fmt.Errorf("password exceeds maximum length of %d", MaxPasswordLength)
	}
	return nil
}

// getRateLimiter returns a rate limiter for the given client address.
func (s *server) getRateLimiter(clientAddr string) *rate.Limiter {
	s.rateLimitersMu.Lock()
	defer s.rateLimitersMu.Unlock()

	limiter, exists := s.rateLimiters[clientAddr]
	if !exists {
		limiter = rate.NewLimiter(RateLimitPerSecond, RateLimitBurst)
		s.rateLimiters[clientAddr] = limiter
	}

	return limiter
}

// Login authenticates a user and returns a JWT token.
// Implements rate limiting, input validation, and secure password verification.
func (s *server) Login(ctx context.Context, r *pb.Request) (*pb.Response, error) {
	// Get client address for rate limiting
	clientAddr := "unknown"
	if p, ok := peer.FromContext(ctx); ok {
		clientAddr = p.Addr.String()
	}

	// Apply rate limiting per client IP
	limiter := s.getRateLimiter(clientAddr)
	if !limiter.Allow() {
		return nil, status.Error(codes.ResourceExhausted, "too many login attempts, please try again later")
	}

	// Validate input
	if err := validateUsername(r.Username); err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid username format")
	}

	if err := validatePassword(r.Password); err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid password format")
	}

	// Verify username
	if r.Username != s.username {
		// Use constant-time comparison pattern (check password even if username wrong)
		// to prevent timing attacks
		bcrypt.CompareHashAndPassword(s.passwordHash, []byte(r.Password))
		return nil, status.Error(codes.PermissionDenied, "invalid credentials")
	}

	// Verify password using bcrypt
	if err := bcrypt.CompareHashAndPassword(s.passwordHash, []byte(r.Password)); err != nil {
		return nil, status.Error(codes.PermissionDenied, "invalid credentials")
	}

	// Generate JWT token
	now := time.Now()
	exp := now.Add(TokenExpiration)

	claims := jwt.MapClaims{
		"sub": r.Username,
		"aud": "hello.service",
		"iss": "auth.service",
		"exp": exp.Unix(),
		"iat": now.Unix(),
		"nbf": now.Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)

	tokenStr, err := token.SignedString(s.jwtKey)
	if err != nil {
		// Don't leak internal error details to client
		return nil, status.Error(codes.Internal, "failed to generate token")
	}

	return &pb.Response{Token: tokenStr}, nil
}
