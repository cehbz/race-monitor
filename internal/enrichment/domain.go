// Package enrichment provides IP and network enrichment for race peers.
//
// The domain model follows 3NF: per-IP data (rDNS, provider from hostname)
// is separated from per-network data (ASN, ISP, datacenter, geo) keyed by
// BGP prefix. Two processing queues match these entities: an IP queue
// (free DNS lookups) and a prefix queue (rate-limited API lookups).
package enrichment

import "time"

// IPInfo holds per-IP enrichment data (rDNS and BGP prefix mapping).
type IPInfo struct {
	IP         string
	RDNS       string // reverse DNS hostname
	BGPPrefix  string // CIDR, FK to NetworkInfo
	Provider   string // from rDNS pattern match (tier 1), overrides network-level
	EnrichedAt time.Time
}

// NetworkInfo holds per-BGP-prefix enrichment data from API lookups.
type NetworkInfo struct {
	BGPPrefix    string  // CIDR, e.g. "185.21.216.0/22"
	ASN          int     // AS number
	ASNOrg       string  // AS organization name
	ISP          string  // company name
	CompanyType  string  // "hosting", "isp", "business"
	IsDatacenter bool    // datacenter flag
	Datacenter   string  // raw datacenter provider name from API
	Provider     string  // resolved brand name (derived)
	City         string
	Region       string
	Country      string  // 2-letter code
	Latitude     float64
	Longitude    float64
	EnrichedAt   time.Time
	Source       string // "ipapi.is", "cymru"
}

// DNSResult holds the output of free DNS lookups for a single IP.
type DNSResult struct {
	RDNS      string // reverse DNS hostname (empty if lookup failed)
	ASN       int    // from Team Cymru
	ASNOrg    string // from Team Cymru
	BGPPrefix string // CIDR from Team Cymru
	Country   string // 2-letter code from Team Cymru
}

// APIResult holds the full output of an ipapi.is lookup.
type APIResult struct {
	ASN          int
	ASNOrg       string
	BGPPrefix    string // asn.route
	ISP          string // company.name
	CompanyType  string // company.type
	CompanyDomain string // company.domain
	IsDatacenter bool
	Datacenter   string // datacenter.datacenter
	DCDomain     string // datacenter.domain
	AbuseEmail   string // abuse.email
	City         string
	Region       string
	Country      string
	Latitude     float64
	Longitude    float64
}
