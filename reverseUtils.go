package pdsql

import (
	"fmt"
	"net"
	"strings"
)

// ParseReverseDNS extracts IP address from PTR query name
// Example: "1.1.168.192.in-addr.arpa." -> "192.168.1.1"
func ParseReverseDNS(qname string) (net.IP, error) {
	// Remove trailing dot if present
	qname = strings.TrimSuffix(qname, ".")
	
	// Convert to lowercase for case-insensitive matching
	qname = strings.ToLower(qname)
	
	// Check for IPv4 reverse DNS suffix
	if strings.HasSuffix(qname, ".in-addr.arpa") {
		return parseIPv4Reverse(qname)
	}
	
	// Check for IPv6 reverse DNS suffix
	if strings.HasSuffix(qname, ".ip6.arpa") {
		return parseIPv6Reverse(qname)
	}
	
	return nil, fmt.Errorf("not a reverse DNS query: %s", qname)
}

func parseIPv4Reverse(qname string) (net.IP, error) {
	// Remove .in-addr.arpa suffix
	prefix := strings.TrimSuffix(qname, ".in-addr.arpa")
	
	// Split by dots and reverse
	parts := strings.Split(prefix, ".")
	if len(parts) != 4 {
		return nil, fmt.Errorf("invalid IPv4 reverse DNS format: %s", qname)
	}
	
	// Reverse the octets
	for i := 0; i < 2; i++ {
		parts[i], parts[3-i] = parts[3-i], parts[i]
	}
	
	// Join and parse
	ipStr := strings.Join(parts, ".")
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil, fmt.Errorf("invalid IP address: %s", ipStr)
	}
	
	return ip, nil
}

func parseIPv6Reverse(qname string) (net.IP, error) {
	// Implementation for IPv6 (optional, can be added later)
	return nil, fmt.Errorf("IPv6 reverse DNS not yet implemented")
}

// IsReverseDNSQuery checks if the query is a reverse DNS lookup
func IsReverseDNSQuery(qname string) bool {
	qname = strings.ToLower(strings.TrimSuffix(qname, "."))
	return strings.HasSuffix(qname, ".in-addr.arpa") || 
	       strings.HasSuffix(qname, ".ip6.arpa")
}

// generatePTRName creates the PTR record name from IP
func generatePTRName(ip net.IP) string {
	if ip4 := ip.To4(); ip4 != nil {
		// IPv4: 192.168.1.1 -> 1.1.168.192.in-addr.arpa
		return fmt.Sprintf("%d.%d.%d.%d.in-addr.arpa", 
			ip4[3], ip4[2], ip4[1], ip4[0])
	}
	// IPv6 handling would go here
	return ""
}