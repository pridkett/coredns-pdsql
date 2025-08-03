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
	// Remove .ip6.arpa suffix
	prefix := strings.TrimSuffix(qname, ".ip6.arpa")
	
	// Split by dots
	parts := strings.Split(prefix, ".")
	
	// IPv6 reverse DNS should have exactly 32 nibbles (hex digits)
	if len(parts) != 32 {
		return nil, fmt.Errorf("invalid IPv6 reverse DNS format: expected 32 nibbles, got %d", len(parts))
	}
	
	// Build IPv6 address from nibbles in reverse order
	var hexDigits []byte
	// Process nibbles from end to beginning
	for i := 31; i >= 0; i-- {
		nibble := parts[i]
		// Validate that each nibble is a single hex digit
		if len(nibble) != 1 || !isHexDigit(nibble[0]) {
			return nil, fmt.Errorf("invalid hex nibble: %s", nibble)
		}
		hexDigits = append(hexDigits, nibble[0])
	}
	
	// Group hex digits into 8 groups of 4
	var groups []string
	for i := 0; i < 8; i++ {
		group := string(hexDigits[i*4 : (i+1)*4])
		groups = append(groups, group)
	}
	
	// Join groups with colons
	ipStr := strings.Join(groups, ":")
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil, fmt.Errorf("invalid IPv6 address: %s", ipStr)
	}
	
	return ip, nil
}

// isHexDigit checks if a byte is a valid hexadecimal digit
func isHexDigit(b byte) bool {
	return (b >= '0' && b <= '9') || (b >= 'a' && b <= 'f') || (b >= 'A' && b <= 'F')
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
	
	// IPv6: Convert to 16-byte representation
	ip6 := ip.To16()
	if ip6 == nil {
		return ""
	}
	
	// Build the reverse notation by converting each byte to two hex nibbles in reverse order
	var nibbles []string
	for i := 15; i >= 0; i-- {
		// Extract low nibble (least significant 4 bits)
		lowNibble := ip6[i] & 0x0F
		nibbles = append(nibbles, fmt.Sprintf("%x", lowNibble))
		
		// Extract high nibble (most significant 4 bits)
		highNibble := (ip6[i] >> 4) & 0x0F
		nibbles = append(nibbles, fmt.Sprintf("%x", highNibble))
	}
	
	// Join all nibbles with dots and append .ip6.arpa
	return strings.Join(nibbles, ".") + ".ip6.arpa"
}