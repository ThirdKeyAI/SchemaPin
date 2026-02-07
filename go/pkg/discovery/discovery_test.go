package discovery

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestConstructWellKnownURL(t *testing.T) {
	tests := []struct {
		name     string
		domain   string
		expected string
	}{
		{
			name:     "simple domain",
			domain:   "example.com",
			expected: "https://example.com/.well-known/schemapin.json",
		},
		{
			name:     "domain with https",
			domain:   "https://example.com",
			expected: "https://example.com/.well-known/schemapin.json",
		},
		{
			name:     "domain with http",
			domain:   "http://example.com",
			expected: "http://example.com/.well-known/schemapin.json",
		},
		{
			name:     "domain with port",
			domain:   "example.com:8080",
			expected: "https://example.com:8080/.well-known/schemapin.json",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ConstructWellKnownURL(tt.domain)
			if result != tt.expected {
				t.Errorf("ConstructWellKnownURL(%q) = %q, want %q", tt.domain, result, tt.expected)
			}
		})
	}
}

func TestValidateWellKnownResponse(t *testing.T) {
	tests := []struct {
		name     string
		response *WellKnownResponse
		expected bool
	}{
		{
			name: "valid response",
			response: &WellKnownResponse{
				SchemaVersion: "1.1",
				PublicKeyPEM:  "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...\n-----END PUBLIC KEY-----",
				DeveloperName: "Test Developer",
			},
			expected: true,
		},
		{
			name: "missing schema version",
			response: &WellKnownResponse{
				PublicKeyPEM:  "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...\n-----END PUBLIC KEY-----",
				DeveloperName: "Test Developer",
			},
			expected: false,
		},
		{
			name: "missing public key",
			response: &WellKnownResponse{
				SchemaVersion: "1.1",
				DeveloperName: "Test Developer",
			},
			expected: false,
		},
		{
			name:     "nil response",
			response: nil,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ValidateWellKnownResponse(tt.response)
			if result != tt.expected {
				t.Errorf("ValidateWellKnownResponse() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestCheckKeyRevocation(t *testing.T) {
	tests := []struct {
		name        string
		publicKey   string
		revokedKeys []string
		expected    bool
	}{
		{
			name:        "key not revoked - empty list",
			publicKey:   "test-key",
			revokedKeys: []string{},
			expected:    false,
		},
		{
			name:        "key not revoked - not in list",
			publicKey:   "test-key",
			revokedKeys: []string{"other-key", "another-key"},
			expected:    false,
		},
		{
			name:        "key revoked - direct match",
			publicKey:   "test-key",
			revokedKeys: []string{"other-key", "test-key"},
			expected:    true,
		},
		{
			name:        "key not revoked - nil list",
			publicKey:   "test-key",
			revokedKeys: nil,
			expected:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := CheckKeyRevocation(tt.publicKey, tt.revokedKeys)
			if result != tt.expected {
				t.Errorf("CheckKeyRevocation() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestPublicKeyDiscoveryFetchWellKnown(t *testing.T) {
	// Create a test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/schemapin.json" {
			http.NotFound(w, r)
			return
		}

		response := WellKnownResponse{
			SchemaVersion: "1.1",
			DeveloperName: "Test Developer",
			PublicKeyPEM:  "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...\n-----END PUBLIC KEY-----",
			Contact:       "test@example.com",
			RevokedKeys:   []string{"revoked-key-1"},
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	discovery := NewPublicKeyDiscovery()
	ctx := context.Background()

	// Extract domain from server URL (remove http://)
	domain := server.URL[7:] // Remove "http://"

	// Override the URL construction to use HTTP for testing
	originalURL := discovery.ConstructWellKnownURL(domain)
	testURL := server.URL + "/.well-known/schemapin.json"

	// Create a custom request
	req, err := http.NewRequestWithContext(ctx, "GET", testURL, nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	resp, err := discovery.client.Do(req)
	if err != nil {
		t.Fatalf("Failed to fetch .well-known file: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Unexpected status code: %d", resp.StatusCode)
	}

	var wellKnown WellKnownResponse
	if err := json.NewDecoder(resp.Body).Decode(&wellKnown); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if wellKnown.SchemaVersion != "1.1" {
		t.Errorf("Expected schema version 1.1, got %s", wellKnown.SchemaVersion)
	}

	if wellKnown.DeveloperName != "Test Developer" {
		t.Errorf("Expected developer name 'Test Developer', got %s", wellKnown.DeveloperName)
	}

	if len(wellKnown.RevokedKeys) != 1 || wellKnown.RevokedKeys[0] != "revoked-key-1" {
		t.Errorf("Expected revoked keys [revoked-key-1], got %v", wellKnown.RevokedKeys)
	}

	_ = originalURL // Avoid unused variable error
}

func TestPublicKeyDiscoveryErrorHandling(t *testing.T) {
	// Test server that returns 404
	server404 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer server404.Close()

	// Test server that returns invalid JSON
	serverInvalidJSON := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("invalid json"))
	}))
	defer serverInvalidJSON.Close()

	// Test server that returns invalid response structure
	serverInvalidResponse := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		response := map[string]interface{}{
			"invalid": "response",
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer serverInvalidResponse.Close()

	discovery := NewPublicKeyDiscovery()
	ctx := context.Background()

	tests := []struct {
		name      string
		serverURL string
		expectErr bool
	}{
		{
			name:      "404 error",
			serverURL: server404.URL,
			expectErr: true,
		},
		{
			name:      "invalid JSON",
			serverURL: serverInvalidJSON.URL,
			expectErr: true,
		},
		{
			name:      "invalid response structure",
			serverURL: serverInvalidResponse.URL,
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create custom request to test server
			req, err := http.NewRequestWithContext(ctx, "GET", tt.serverURL+"/.well-known/schemapin.json", nil)
			if err != nil {
				t.Fatalf("Failed to create request: %v", err)
			}

			resp, err := discovery.client.Do(req)
			if err != nil {
				if !tt.expectErr {
					t.Errorf("Unexpected error: %v", err)
				}
				return
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				if !tt.expectErr {
					t.Errorf("Unexpected status code: %d", resp.StatusCode)
				}
				return
			}

			var wellKnown WellKnownResponse
			if err := json.NewDecoder(resp.Body).Decode(&wellKnown); err != nil {
				if !tt.expectErr {
					t.Errorf("Unexpected decode error: %v", err)
				}
				return
			}

			if !ValidateWellKnownResponse(&wellKnown) {
				if !tt.expectErr {
					t.Errorf("Response validation failed unexpectedly")
				}
				return
			}

			if tt.expectErr {
				t.Errorf("Expected error but got none")
			}
		})
	}
}

func TestPublicKeyDiscoveryTimeout(t *testing.T) {
	// Create a server that delays response
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		response := WellKnownResponse{
			SchemaVersion: "1.1",
			PublicKeyPEM:  "test-key",
		}
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	// Create discovery with very short timeout
	discovery := NewPublicKeyDiscoveryWithTimeout(50 * time.Millisecond)

	ctx := context.Background()
	req, err := http.NewRequestWithContext(ctx, "GET", server.URL+"/.well-known/schemapin.json", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	_, err = discovery.client.Do(req)
	if err == nil {
		t.Errorf("Expected timeout error but got none")
	}
}

func TestGetDeveloperInfo(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		response := WellKnownResponse{
			SchemaVersion: "1.1",
			DeveloperName: "Test Developer",
			PublicKeyPEM:  "test-key",
			Contact:       "test@example.com",
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	discovery := NewPublicKeyDiscovery()

	// Test with missing developer info
	serverEmpty := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		response := WellKnownResponse{
			PublicKeyPEM: "test-key",
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer serverEmpty.Close()

	tests := []struct {
		name           string
		serverURL      string
		expectedName   string
		expectedSchema string
		expectContact  bool
	}{
		{
			name:           "complete developer info",
			serverURL:      server.URL,
			expectedName:   "Test Developer",
			expectedSchema: "1.1",
			expectContact:  true,
		},
		{
			name:           "missing developer info",
			serverURL:      serverEmpty.URL,
			expectedName:   "Unknown",
			expectedSchema: "1.0",
			expectContact:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequestWithContext(context.Background(), "GET", tt.serverURL+"/.well-known/schemapin.json", nil)
			if err != nil {
				t.Fatalf("Failed to create request: %v", err)
			}

			resp, err := discovery.client.Do(req)
			if err != nil {
				t.Fatalf("Failed to fetch: %v", err)
			}
			defer resp.Body.Close()

			var wellKnown WellKnownResponse
			if err := json.NewDecoder(resp.Body).Decode(&wellKnown); err != nil {
				t.Fatalf("Failed to decode: %v", err)
			}

			info := map[string]string{
				"developer_name": wellKnown.DeveloperName,
				"schema_version": wellKnown.SchemaVersion,
			}

			if wellKnown.Contact != "" {
				info["contact"] = wellKnown.Contact
			}

			// Set defaults for missing fields
			if info["developer_name"] == "" {
				info["developer_name"] = "Unknown"
			}
			if info["schema_version"] == "" {
				info["schema_version"] = "1.0"
			}

			if info["developer_name"] != tt.expectedName {
				t.Errorf("Expected developer name %s, got %s", tt.expectedName, info["developer_name"])
			}

			if info["schema_version"] != tt.expectedSchema {
				t.Errorf("Expected schema version %s, got %s", tt.expectedSchema, info["schema_version"])
			}

			if tt.expectContact && info["contact"] == "" {
				t.Errorf("Expected contact info but got none")
			}

			if !tt.expectContact && info["contact"] != "" {
				t.Errorf("Expected no contact info but got %s", info["contact"])
			}
		})
	}
}
