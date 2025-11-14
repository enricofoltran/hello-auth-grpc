package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultConfigDir(t *testing.T) {
	// Test with custom env var
	customDir := "/tmp/custom-config"
	os.Setenv("HELLO_CONFIG_DIR", customDir)
	defer os.Unsetenv("HELLO_CONFIG_DIR")

	got := DefaultConfigDir()
	if got != customDir {
		t.Errorf("DefaultConfigDir() = %v, want %v", got, customDir)
	}

	// Test with default (HOME/.hello)
	os.Unsetenv("HELLO_CONFIG_DIR")
	got = DefaultConfigDir()
	expected := filepath.Join(os.Getenv("HOME"), ".hello")
	if got != expected {
		t.Errorf("DefaultConfigDir() = %v, want %v", got, expected)
	}
}

func TestWithConfigDir(t *testing.T) {
	testFile := "test.pem"
	got := WithConfigDir(testFile)

	// Should combine config dir with file
	if !filepath.IsAbs(got) {
		t.Errorf("WithConfigDir() should return absolute path, got %v", got)
	}

	if filepath.Base(got) != testFile {
		t.Errorf("WithConfigDir() should preserve filename, got %v", got)
	}
}
