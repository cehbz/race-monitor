package enrichment

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// NetDNSResolver implements DNSResolver using the standard library net package
// for reverse DNS and Team Cymru DNS for ASN/prefix lookups.
type NetDNSResolver struct {
	resolver *net.Resolver
}

// NewDNSResolver creates a DNSResolver using the system DNS.
func NewDNSResolver() *NetDNSResolver {
	return &NetDNSResolver{
		resolver: net.DefaultResolver,
	}
}

// Resolve performs rDNS and Team Cymru lookups for an IP.
// Returns partial results on individual lookup failures.
func (r *NetDNSResolver) Resolve(ctx context.Context, ip string) (*DNSResult, error) {
	result := &DNSResult{}

	// Reverse DNS
	names, err := r.resolver.LookupAddr(ctx, ip)
	if err == nil && len(names) > 0 {
		// Remove trailing dot from FQDN
		result.RDNS = strings.TrimSuffix(names[0], ".")
	}

	// Team Cymru: query <reversed-ip>.origin.asn.cymru.com TXT
	cymruName := reverseIP(ip) + ".origin.asn.cymru.com"
	txts, err := r.resolver.LookupTXT(ctx, cymruName)
	if err == nil && len(txts) > 0 {
		parseCymruOrigin(txts[0], result)
	}

	return result, nil
}

// reverseIP reverses the octets of an IPv4 address for DNS queries.
// "1.2.3.4" → "4.3.2.1"
func reverseIP(ip string) string {
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return ip
	}
	return parts[3] + "." + parts[2] + "." + parts[1] + "." + parts[0]
}

// parseCymruOrigin parses a Team Cymru origin TXT record.
// Format: "ASN | prefix | CC | RIR | date"
// Example: "15169 | 8.8.8.0/24 | US | arin | 2014-03-14"
func parseCymruOrigin(txt string, result *DNSResult) {
	fields := strings.Split(txt, "|")
	if len(fields) < 3 {
		return
	}

	asnStr := strings.TrimSpace(fields[0])
	if asn, err := strconv.Atoi(asnStr); err == nil {
		result.ASN = asn
	}

	result.BGPPrefix = strings.TrimSpace(fields[1])
	result.Country = strings.TrimSpace(fields[2])

	// ASN org comes from a separate peer query, but Cymru origin gives us
	// the essential ASN + prefix. We'll get org from ipapi.is if available.
}

// CymruASNName queries Team Cymru for the ASN organization name.
// Query: AS<number>.asn.cymru.com TXT → "ASN | CC | RIR | date | org"
func (r *NetDNSResolver) CymruASNName(ctx context.Context, asn int) (string, error) {
	name := fmt.Sprintf("AS%d.asn.cymru.com", asn)
	txts, err := r.resolver.LookupTXT(ctx, name)
	if err != nil || len(txts) == 0 {
		return "", err
	}

	fields := strings.Split(txts[0], "|")
	if len(fields) < 5 {
		return "", nil
	}
	return strings.TrimSpace(fields[4]), nil
}
