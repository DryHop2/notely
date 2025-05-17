package auth

import (
	"errors"
	"net/http"
	"testing"
)

var errMalformedAuthHeader = errors.New("malformed authorization header") // promote this to match by type

func TestGetAPIKey(t *testing.T) {
	tests := map[string]struct {
		authHeader    string
		expectedKey   string
		expectedError error
	}{
		"valid header": {
			authHeader:    "ApiKey abc123",
			expectedKey:   "abc123",
			expectedError: nil,
		},
		"missing header": {
			authHeader:    "",
			expectedKey:   "",
			expectedError: ErrNoAuthHeaderIncluded,
		},
		"malformed header (wrong scheme)": {
			authHeader:    "Bearer abc123",
			expectedKey:   "",
			expectedError: errMalformedAuthHeader,
		},
		"malformed header (missing key)": {
			authHeader:    "ApiKey",
			expectedKey:   "",
			expectedError: errMalformedAuthHeader,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			headers := http.Header{}
			if tc.authHeader != "" {
				headers.Set("Authorization", tc.authHeader)
			}

			key, err := GetAPIKey(headers)

			if key != tc.expectedKey {
				t.Errorf("expected key '%s', got '%s'", tc.expectedKey, key)
			}

			switch {
			case err != nil && tc.expectedError != nil && err.Error() != tc.expectedError.Error():
				t.Errorf("expected error '%v', got '%v'", tc.expectedError, err)
			case err == nil && tc.expectedError != nil:
				t.Errorf("expected error '%v', got nil", tc.expectedError)
			case err != nil && tc.expectedError == nil:
				t.Errorf("expected no error, got '%v'", err)
			}
		})
	}
}
