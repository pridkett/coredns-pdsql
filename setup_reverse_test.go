package pdsql

import (
	"testing"

	"github.com/coredns/caddy"
)

func TestSetupReverse(t *testing.T) {
	tests := []struct {
		name               string
		input              string
		expectedError      bool
		expectReverse      bool
		expectFirstOnly    bool
	}{
		{
			name: "reverse option enabled",
			input: `pdsql sqlite3 ":memory:" {
				reverse
			}`,
			expectedError:   false,
			expectReverse:   true,
			expectFirstOnly: false,
		},
		{
			name: "reverse option not specified",
			input: `pdsql sqlite3 ":memory:" {
				debug db
			}`,
			expectedError:   false,
			expectReverse:   false,
			expectFirstOnly: false,
		},
		{
			name: "reverse with other options",
			input: `pdsql sqlite3 ":memory:" {
				debug db
				reverse
				debug requests
			}`,
			expectedError:   false,
			expectReverse:   true,
			expectFirstOnly: false,
		},
		{
			name:            "empty config block",
			input:           `pdsql sqlite3 ":memory:" { }`,
			expectedError:   false,
			expectReverse:   false,
			expectFirstOnly: false,
		},
		{
			name:            "no config block",
			input:           `pdsql sqlite3 ":memory:"`,
			expectedError:   false,
			expectReverse:   false,
			expectFirstOnly: false,
		},
		{
			name: "reverse option with firstonly",
			input: `pdsql sqlite3 ":memory:" {
				reverse firstonly
			}`,
			expectedError:   false,
			expectReverse:   true,
			expectFirstOnly: true,
		},
		{
			name: "reverse option with invalid argument",
			input: `pdsql sqlite3 ":memory:" {
				reverse invalid
			}`,
			expectedError:   true,
			expectReverse:   false,
			expectFirstOnly: false,
		},
		{
			name: "reverse option with multiple arguments should fail",
			input: `pdsql sqlite3 ":memory:" {
				reverse firstonly extra
			}`,
			expectedError:   true,
			expectReverse:   false,
			expectFirstOnly: false,
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

			// Check if the ReverseFirstOnly field is set correctly
			if backend.ReverseFirstOnly != tt.expectFirstOnly {
				t.Errorf("Expected ReverseFirstOnly to be %v, got %v", tt.expectFirstOnly, backend.ReverseFirstOnly)
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