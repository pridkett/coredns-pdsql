package pdsql

import (
	"net"
	"testing"
)

func TestParseReverseDNS(t *testing.T) {
	tests := []struct {
		name     string
		qname    string
		expected string
		wantErr  bool
	}{
		{
			name:     "valid IPv4 with trailing dot",
			qname:    "1.1.168.192.in-addr.arpa.",
			expected: "192.168.1.1",
			wantErr:  false,
		},
		{
			name:     "valid IPv4 without trailing dot",
			qname:    "10.20.30.40.in-addr.arpa",
			expected: "40.30.20.10",
			wantErr:  false,
		},
		{
			name:     "valid IPv4 single digit octets",
			qname:    "1.2.3.4.in-addr.arpa",
			expected: "4.3.2.1",
			wantErr:  false,
		},
		{
			name:     "valid IPv4 with zeros",
			qname:    "0.0.0.10.in-addr.arpa",
			expected: "10.0.0.0",
			wantErr:  false,
		},
		{
			name:     "invalid format - not reverse DNS",
			qname:    "example.com",
			expected: "",
			wantErr:  true,
		},
		{
			name:     "invalid format - regular domain",
			qname:    "not.a.reverse.query",
			expected: "",
			wantErr:  true,
		},
		{
			name:     "incomplete IPv4 - only 3 octets",
			qname:    "1.168.192.in-addr.arpa",
			expected: "",
			wantErr:  true,
		},
		{
			name:     "incomplete IPv4 - only 2 octets",
			qname:    "1.168.in-addr.arpa",
			expected: "",
			wantErr:  true,
		},
		{
			name:     "too many octets",
			qname:    "1.2.3.4.5.in-addr.arpa",
			expected: "",
			wantErr:  true,
		},
		{
			name:     "invalid octet values",
			qname:    "256.1.1.1.in-addr.arpa",
			expected: "",
			wantErr:  true,
		},
		{
			name:     "IPv6 reverse DNS - not implemented",
			qname:    "b.a.9.8.7.6.5.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa",
			expected: "",
			wantErr:  true,
		},
		{
			name:     "mixed case should work",
			qname:    "1.1.168.192.IN-ADDR.ARPA",
			expected: "192.168.1.1",
			wantErr:  false,
		},
		{
			name:     "empty string",
			qname:    "",
			expected: "",
			wantErr:  true,
		},
		{
			name:     "just the suffix",
			qname:    ".in-addr.arpa",
			expected: "",
			wantErr:  true,
		},
		{
			name:     "non-numeric octets",
			qname:    "a.b.c.d.in-addr.arpa",
			expected: "",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip, err := ParseReverseDNS(tt.qname)
			if tt.wantErr {
				if err == nil {
					t.Errorf("ParseReverseDNS() expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("ParseReverseDNS() unexpected error: %v", err)
				} else if ip.String() != tt.expected {
					t.Errorf("ParseReverseDNS() = %v, want %v", ip.String(), tt.expected)
				}
			}
		})
	}
}

func TestIsReverseDNSQuery(t *testing.T) {
	tests := []struct {
		name     string
		qname    string
		expected bool
	}{
		{
			name:     "valid IPv4 reverse with trailing dot",
			qname:    "1.1.168.192.in-addr.arpa.",
			expected: true,
		},
		{
			name:     "valid IPv4 reverse without trailing dot",
			qname:    "1.1.168.192.in-addr.arpa",
			expected: true,
		},
		{
			name:     "valid IPv6 reverse",
			qname:    "b.a.9.8.7.6.5.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa",
			expected: true,
		},
		{
			name:     "regular domain",
			qname:    "example.com",
			expected: false,
		},
		{
			name:     "subdomain of example.com",
			qname:    "sub.example.com",
			expected: false,
		},
		{
			name:     "contains in-addr.arpa but not at end",
			qname:    "in-addr.arpa.example.com",
			expected: false,
		},
		{
			name:     "mixed case IPv4",
			qname:    "1.1.168.192.IN-ADDR.ARPA",
			expected: true,
		},
		{
			name:     "mixed case IPv6",
			qname:    "1.2.3.4.IP6.ARPA",
			expected: true,
		},
		{
			name:     "empty string",
			qname:    "",
			expected: false,
		},
		{
			name:     "just dots",
			qname:    "....",
			expected: false,
		},
		{
			name:     "incomplete reverse DNS",
			qname:    "192.in-addr.arpa",
			expected: true, // Still a reverse DNS query, just incomplete
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsReverseDNSQuery(tt.qname)
			if result != tt.expected {
				t.Errorf("IsReverseDNSQuery(%q) = %v, want %v", tt.qname, result, tt.expected)
			}
		})
	}
}

func TestGeneratePTRName(t *testing.T) {
	tests := []struct {
		name     string
		ip       net.IP
		expected string
	}{
		{
			name:     "IPv4 192.168.1.1",
			ip:       net.ParseIP("192.168.1.1"),
			expected: "1.1.168.192.in-addr.arpa",
		},
		{
			name:     "IPv4 10.0.0.1",
			ip:       net.ParseIP("10.0.0.1"),
			expected: "1.0.0.10.in-addr.arpa",
		},
		{
			name:     "IPv4 255.255.255.255",
			ip:       net.ParseIP("255.255.255.255"),
			expected: "255.255.255.255.in-addr.arpa",
		},
		{
			name:     "IPv4 0.0.0.0",
			ip:       net.ParseIP("0.0.0.0"),
			expected: "0.0.0.0.in-addr.arpa",
		},
		{
			name:     "IPv6 - not implemented",
			ip:       net.ParseIP("2001:db8::1"),
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := generatePTRName(tt.ip)
			if result != tt.expected {
				t.Errorf("generatePTRName(%v) = %v, want %v", tt.ip, result, tt.expected)
			}
		})
	}
}