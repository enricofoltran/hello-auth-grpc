// Package config provides shared configuration utilities for the hello-auth-grpc services.
package config

import (
	"os"
	"path/filepath"
)

// DefaultConfigDir returns the default configuration directory.
// Can be overridden with the HELLO_CONFIG_DIR environment variable.
func DefaultConfigDir() string {
	if dir := os.Getenv("HELLO_CONFIG_DIR"); dir != "" {
		return dir
	}
	return filepath.Join(os.Getenv("HOME"), ".hello")
}

// WithConfigDir returns the full path for a file within the configuration directory.
func WithConfigDir(path string) string {
	return filepath.Join(DefaultConfigDir(), path)
}
