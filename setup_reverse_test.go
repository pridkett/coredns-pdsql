package pdsql

import (
	"testing"

	"github.com/coredns/caddy"
)

func TestSetupReverse(t *testing.T) {
	tests := []struct {
		name          string
		input         string
		expectedError bool
		expectReverse bool
	}{
		{
			name: "reverse option enabled",
			input: `pdsql postgres "host=localhost dbname=test" {
				reverse
			}`,
			expectedError: false,
			expectReverse: true,
		},
		{
			name: "reverse option not specified",
			input: `pdsql postgres "host=localhost dbname=test" {
				debug db
			}`,
			expectedError: false,
			expectReverse: false,
		},
		{
			name: "reverse with other options",
			input: `pdsql postgres "host=localhost dbname=test" {
				debug db
				reverse
				debug requests
			}`,
			expectedError: false,
			expectReverse: true,
		},
		{
			name:          "empty config block",
			input:         `pdsql postgres "host=localhost dbname=test" {}`,
			expectedError: false,
			expectReverse: false,
		},
		{
			name:          "no config block",
			input:         `pdsql postgres "host=localhost dbname=test"`,
			expectedError: false,
			expectReverse: false,
		},
		{
			name: "reverse option with argument should fail",
			input: `pdsql postgres "host=localhost dbname=test" {
				reverse true
			}`,
			expectedError: true,
			expectReverse: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := caddy.NewTestController("dns", tt.input)
			backend, err := ParseConfig(c)

			if tt.expectedError {
				if err == nil {
					t.Errorf("Expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			if backend == nil {
				t.Fatal("Backend is nil")
			}

			// Check if the Reverse field is set correctly
			if backend.Reverse != tt.expectReverse {
				t.Errorf("Expected Reverse to be %v, got %v", tt.expectReverse, backend.Reverse)
			}
		})
	}
}

func TestReverseIntegrationWithSetup(t *testing.T) {
	// Test that reverse DNS configuration integrates with the full setup
	input := `pdsql sqlite3 ":memory:" {
		reverse
		debug db
	}`

	c := caddy.NewTestController("dns", input)
	err := setup(c)

	if err != nil {
		t.Fatalf("setup() error = %v", err)
	}

	// Verify the plugin was registered
	// This would require accessing the plugin registry, which is not directly testable
	// But we can at least ensure setup doesn't error
}