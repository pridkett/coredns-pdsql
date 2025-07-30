package pdsql_test

import (
	"context"
	"fmt"
	"net"
	"testing"

	"github.com/coredns/coredns/plugin/pkg/dnstest"
	"github.com/coredns/coredns/plugin/test"
	"github.com/glebarez/sqlite"
	"github.com/miekg/dns"
	"gorm.io/gorm"
	"github.com/wenerme/coredns-pdsql"
	"github.com/wenerme/coredns-pdsql/pdnsmodel"
)

func TestResolveReverseDNS(t *testing.T) {
	// Setup test database
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	// db doesn't need explicit close with gorm v2

	// Create tables
	db.AutoMigrate(&pdnsmodel.Domain{}, &pdnsmodel.Record{})

	// Insert test data
	domain := pdnsmodel.Domain{
		ID:   1,
		Name: "example.com",
		Type: "NATIVE",
	}
	db.Create(&domain)

	testRecords := []pdnsmodel.Record{
		{
			DomainId: 1,
			Name:     "host1.example.com",
			Type:     "A",
			Content:  "192.168.1.1",
			Ttl:      300,
			Disabled: false,
		},
		{
			DomainId: 1,
			Name:     "host2.example.com",
			Type:     "A",
			Content:  "192.168.1.1",
			Ttl:      300,
			Disabled: false,
		},
		{
			DomainId: 1,
			Name:     "host3.example.com",
			Type:     "A",
			Content:  "192.168.1.2",
			Ttl:      300,
			Disabled: false,
		},
		{
			DomainId: 1,
			Name:     "disabled.example.com",
			Type:     "A",
			Content:  "192.168.1.3",
			Ttl:      300,
			Disabled: true,
		},
		{
			DomainId: 1,
			Name:     "ipv6.example.com",
			Type:     "AAAA",
			Content:  "2001:db8::1",
			Ttl:      300,
			Disabled: false,
		},
	}

	for _, r := range testRecords {
		db.Create(&r)
	}

	backend := &pdsql.PowerDNSGenericSQLBackend{
		DB:    db,
		Debug: false,
	}

	tests := []struct {
		name         string
		ip           string
		expectedLen  int
		expectedHosts []string
	}{
		{
			name:         "single host for IP",
			ip:           "192.168.1.2",
			expectedLen:  1,
			expectedHosts: []string{"host3.example.com"},
		},
		{
			name:         "multiple hosts for same IP",
			ip:           "192.168.1.1",
			expectedLen:  2,
			expectedHosts: []string{"host1.example.com", "host2.example.com"},
		},
		{
			name:         "no hosts for IP",
			ip:           "192.168.1.100",
			expectedLen:  0,
			expectedHosts: []string{},
		},
		{
			name:         "disabled record should not be returned",
			ip:           "192.168.1.3",
			expectedLen:  0,
			expectedHosts: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			if ip == nil {
				t.Fatalf("Invalid IP address: %s", tt.ip)
			}

			records, err := backend.ResolveReverseDNS(ip)
			if err != nil {
				t.Fatalf("ResolveReverseDNS() error = %v", err)
			}

			if len(records) != tt.expectedLen {
				t.Errorf("ResolveReverseDNS() returned %d records, want %d", len(records), tt.expectedLen)
			}

			// Check that all records are PTR type
			for _, record := range records {
				if record.Type != "PTR" {
					t.Errorf("Expected PTR record, got %s", record.Type)
				}

				// Check that the PTR name is correct
				expectedPTRName := generatePTRName(ip)
				if record.Name != expectedPTRName {
					t.Errorf("Expected PTR name %s, got %s", expectedPTRName, record.Name)
				}
			}

			// Check that all expected hosts are present
			foundHosts := make(map[string]bool)
			for _, record := range records {
				foundHosts[record.Content] = true
			}

			for _, expectedHost := range tt.expectedHosts {
				if !foundHosts[expectedHost] {
					t.Errorf("Expected host %s not found in results", expectedHost)
				}
			}
		})
	}
}

func TestServeDNSWithReverseDNS(t *testing.T) {
	// Setup test database
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	// db doesn't need explicit close with gorm v2

	// Create tables
	db.AutoMigrate(&pdnsmodel.Domain{}, &pdnsmodel.Record{})

	// Insert test data
	domain := pdnsmodel.Domain{
		ID:   1,
		Name: "example.com",
		Type: "NATIVE",
	}
	db.Create(&domain)

	records := []pdnsmodel.Record{
		{
			DomainId: 1,
			Name:     "host1.example.com",
			Type:     "A",
			Content:  "192.168.1.1",
			Ttl:      300,
			Disabled: false,
		},
		{
			DomainId: 1,
			Name:     "host2.example.com",
			Type:     "A",
			Content:  "10.0.0.1",
			Ttl:      600,
			Disabled: false,
		},
	}

	for _, r := range records {
		db.Create(&r)
	}

	tests := []struct {
		name          string
		qname         string
		qtype         uint16
		reverseEnabled bool
		expectedRcode  int
		expectedAnswer int
		expectedType   uint16
		expectedContent string
	}{
		{
			name:          "PTR query with reverse enabled",
			qname:         "1.1.168.192.in-addr.arpa.",
			qtype:         dns.TypePTR,
			reverseEnabled: true,
			expectedRcode:  dns.RcodeSuccess,
			expectedAnswer: 1,
			expectedType:   dns.TypePTR,
			expectedContent: "host1.example.com.",
		},
		{
			name:          "PTR query with reverse disabled",
			qname:         "1.1.168.192.in-addr.arpa.",
			qtype:         dns.TypePTR,
			reverseEnabled: false,
			expectedRcode:  dns.RcodeNameError,
			expectedAnswer: 0,
			expectedType:   0,
			expectedContent: "",
		},
		{
			name:          "PTR query for non-existent IP",
			qname:         "100.100.168.192.in-addr.arpa.",
			qtype:         dns.TypePTR,
			reverseEnabled: true,
			expectedRcode:  dns.RcodeNameError,
			expectedAnswer: 0,
			expectedType:   0,
			expectedContent: "",
		},
		{
			name:          "Regular A query should still work",
			qname:         "host1.example.com.",
			qtype:         dns.TypeA,
			reverseEnabled: true,
			expectedRcode:  dns.RcodeSuccess,
			expectedAnswer: 1,
			expectedType:   dns.TypeA,
			expectedContent: "192.168.1.1",
		},
		{
			name:          "Invalid PTR format",
			qname:         "invalid.ptr.format.in-addr.arpa.",
			qtype:         dns.TypePTR,
			reverseEnabled: true,
			expectedRcode:  dns.RcodeNameError,
			expectedAnswer: 0,
			expectedType:   0,
			expectedContent: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			backend := &pdsql.PowerDNSGenericSQLBackend{
				DB:    db,
				Debug: false,
			}

			m := new(dns.Msg)
			m.SetQuestion(tt.qname, tt.qtype)

			rec := dnstest.NewRecorder(&test.ResponseWriter{})
			code, err := backend.ServeDNS(context.Background(), rec, m)

			if err != nil && code != dns.RcodeNameError {
				t.Fatalf("ServeDNS() error = %v", err)
			}

			if code != tt.expectedRcode {
				t.Errorf("ServeDNS() code = %v, want %v", code, tt.expectedRcode)
			}

			if len(rec.Msg.Answer) != tt.expectedAnswer {
				t.Errorf("Expected %d answers, got %d", tt.expectedAnswer, len(rec.Msg.Answer))
			}

			if tt.expectedAnswer > 0 && len(rec.Msg.Answer) > 0 {
				answer := rec.Msg.Answer[0]
				if answer.Header().Rrtype != tt.expectedType {
					t.Errorf("Expected answer type %d, got %d", tt.expectedType, answer.Header().Rrtype)
				}

				switch tt.expectedType {
				case dns.TypePTR:
					if ptr, ok := answer.(*dns.PTR); ok {
						if ptr.Ptr != tt.expectedContent {
							t.Errorf("Expected PTR content %s, got %s", tt.expectedContent, ptr.Ptr)
						}
					}
				case dns.TypeA:
					if a, ok := answer.(*dns.A); ok {
						if a.A.String() != tt.expectedContent {
							t.Errorf("Expected A content %s, got %s", tt.expectedContent, a.A.String())
						}
					}
				}
			}
		})
	}
}

// Helper function to generate PTR name - this will be replaced by the actual implementation
func generatePTRName(ip net.IP) string {
	if ip4 := ip.To4(); ip4 != nil {
		return fmt.Sprintf("%d.%d.%d.%d.in-addr.arpa", ip4[3], ip4[2], ip4[1], ip4[0])
	}
	return ""
}