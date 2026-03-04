package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKeySuccess(t *testing.T) {
	header := http.Header{}
	header.Set("Authorization", "ApiKey super-secret-key")

	result, err := GetAPIKey(header)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if result != "super-secret-key" {
		t.Fatalf("expected 'super-secret-key', got %s", result)
	}
}

func TestGetAPIKeyNoHeader(t *testing.T) {
	headers := http.Header{}

	_, err := GetAPIKey(headers)
	if err != ErrNoAuthHeaderIncluded {
		t.Fatalf("expected error %v, got %v", ErrNoAuthHeaderIncluded, err)
	}
}

func TestGetAPIKeyInvalidHeader(t *testing.T) {
	headers := http.Header{}
	headers.Set("Authorization", "InvalidHeaderValue")

	result, err := GetAPIKey(headers)
	if err != nil {
		t.Fatalf("expected error, got nil")
	}

	if result != "" {
		t.Fatalf("expected empty result, got %s", result)
	}

	if err.Error() != "malformed authorization header" {
		t.Fatalf("expected error 'malformed authorization header', got %v", err)
	}
}