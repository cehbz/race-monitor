package enrichment

import "context"

// IPStore persists per-IP enrichment data.
type IPStore interface {
	// GetIP returns the IPInfo for an IP, or nil if not found.
	GetIP(ctx context.Context, ip string) (*IPInfo, error)
	// PutIP inserts or replaces an IPInfo record.
	PutIP(ctx context.Context, info *IPInfo) error
	// BackfillProvider sets provider on ip_dns rows matching a BGP prefix
	// where provider is currently empty.
	BackfillProvider(ctx context.Context, bgpPrefix, provider string) error
}

// NetworkStore persists per-BGP-prefix enrichment data.
type NetworkStore interface {
	// GetNetwork returns the NetworkInfo for a BGP prefix, or nil if not found.
	GetNetwork(ctx context.Context, prefix string) (*NetworkInfo, error)
	// PutNetwork inserts or replaces a NetworkInfo record.
	PutNetwork(ctx context.Context, info *NetworkInfo) error
	// PickIPForPrefix returns any IP from ip_dns that maps to the given prefix.
	// Used to select a representative IP for the ipapi.is lookup.
	PickIPForPrefix(ctx context.Context, prefix string) (string, error)
}

// IPQueue provides access to the IP enrichment queue (populated by the Go daemon).
type IPQueue interface {
	// FetchBatch returns up to limit IPs from the enrichment queue.
	FetchBatch(ctx context.Context, limit int) ([]string, error)
	// Remove deletes an IP from the enrichment queue.
	Remove(ctx context.Context, ip string) error
}

// PrefixQueue provides access to the BGP prefix enrichment queue.
type PrefixQueue interface {
	// Enqueue adds a BGP prefix to the queue (idempotent).
	Enqueue(ctx context.Context, prefix string) error
	// FetchBatch returns up to limit prefixes from the queue.
	FetchBatch(ctx context.Context, limit int) ([]string, error)
	// Remove deletes a prefix from the queue.
	Remove(ctx context.Context, prefix string) error
}

// DNSResolver performs free DNS lookups (reverse DNS + Team Cymru).
type DNSResolver interface {
	// Resolve performs rDNS and Team Cymru lookups for an IP.
	// Returns partial results on individual lookup failures.
	Resolve(ctx context.Context, ip string) (*DNSResult, error)
}

// NetworkLookup performs rate-limited API lookups for network metadata.
type NetworkLookup interface {
	// Lookup queries ipapi.is for full network metadata.
	Lookup(ctx context.Context, ip string) (*APIResult, error)
}
