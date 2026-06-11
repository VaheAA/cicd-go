package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name        string
		header      string
		expected    string
		expectError bool
		errorMsg    string
	}{
		{
			name:     "valid API key",
			header:   "ApiKey my-secret-key",
			expected: "my-secret-key",
		},
		{
			name:        "missing auth header",
			header:      "",
			expectError: true,
			errorMsg:    ErrNoAuthHeaderIncluded.Error(),
		},
		{
			name:        "wrong scheme (Bearer instead of ApiKey)",
			header:      "Bearer some-token",
			expectError: true,
			errorMsg:    "malformed authorization header",
		},
		{
			name:        "no space / missing key value",
			header:      "ApiKey",
			expectError: true,
			errorMsg:    "malformed authorization header",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			headers := http.Header{}
			if tc.header != "" {
				headers.Set("Authorization", tc.header)
			}

			key, err := GetAPIKey(headers)

			if tc.expectError {
				if err == nil {
					t.Fatalf("expected error but got nil")
				}
				if err.Error() != tc.errorMsg {
					t.Errorf("expected error %q, got %q", tc.errorMsg, err.Error())
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if key != tc.expected {
				t.Errorf("expected key %q, got %q", tc.expected, key)
			}
		})
	}
}
