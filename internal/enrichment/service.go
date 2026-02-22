package enrichment

import (
	"context"
	"log/slog"
	"net"
	"sync"
	"time"
)

// RateLimiter tracks daily API call budget.
type RateLimiter struct {
	mu       sync.Mutex
	count    int
	limit    int
	resetDay int // day of year when count was last reset
}

// NewRateLimiter creates a rate limiter with the given daily limit.
func NewRateLimiter(dailyLimit int) *RateLimiter {
	return &RateLimiter{
		limit:    dailyLimit,
		resetDay: time.Now().UTC().YearDay(),
	}
}

// TryAcquire returns true if a call can be made, decrementing the budget.
func (r *RateLimiter) TryAcquire() bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	today := time.Now().UTC().YearDay()
	if today != r.resetDay {
		r.count = 0
		r.resetDay = today
	}

	if r.count >= r.limit {
		return false
	}
	r.count++
	return true
}

// Remaining returns the number of API calls left today.
func (r *RateLimiter) Remaining() int {
	r.mu.Lock()
	defer r.mu.Unlock()

	today := time.Now().UTC().YearDay()
	if today != r.resetDay {
		return r.limit
	}
	return r.limit - r.count
}

// moreSpecificPrefix returns whichever CIDR prefix has the longer mask
// (more specific in BGP routing terms). Falls back to cymru if the API
// prefix is empty or unparseable.
func moreSpecificPrefix(cymru, api string) string {
	if api == "" {
		return cymru
	}
	_, cymruNet, errC := net.ParseCIDR(cymru)
	_, apiNet, errA := net.ParseCIDR(api)
	if errC != nil {
		return api
	}
	if errA != nil {
		return cymru
	}
	cymruOnes, _ := cymruNet.Mask.Size()
	apiOnes, _ := apiNet.Mask.Size()
	if apiOnes > cymruOnes {
		return api
	}
	return cymru
}

// IPEnricher processes the IP queue: rDNS + Cymru lookups, writes ip_dns,
// enqueues unknown prefixes to the prefix queue.
type IPEnricher struct {
	store    *SQLiteStore
	resolver DNSResolver
	logger   *slog.Logger
}

// NewIPEnricher creates an IP enricher.
func NewIPEnricher(store *SQLiteStore, resolver DNSResolver, logger *slog.Logger) *IPEnricher {
	return &IPEnricher{store: store, resolver: resolver, logger: logger}
}

// ProcessBatch fetches up to batchSize IPs from the queue and enriches them.
// Returns the number of IPs processed and whether new prefixes were enqueued.
func (e *IPEnricher) ProcessBatch(ctx context.Context, batchSize int) (processed int, newPrefixes bool, err error) {
	ips, err := e.store.FetchBatch(ctx, batchSize)
	if err != nil {
		return 0, false, err
	}

	for _, ip := range ips {
		// Already enriched? remove from queue and skip
		existing, err := e.store.GetIP(ctx, ip)
		if err != nil {
			e.logger.Warn("checking existing IP", "ip", ip, "error", err)
			continue
		}
		if existing != nil {
			e.store.Remove(ctx, ip)
			processed++
			continue
		}

		// DNS lookups (free, unlimited)
		dns, err := e.resolver.Resolve(ctx, ip)
		if err != nil {
			e.logger.Warn("DNS resolve failed", "ip", ip, "error", err)
			dns = &DNSResult{}
		}

		// Tier 1: rDNS pattern match
		provider := MatchRDNS(dns.RDNS)

		info := &IPInfo{
			IP:         ip,
			RDNS:       dns.RDNS,
			BGPPrefix:  dns.BGPPrefix,
			Provider:   provider,
			EnrichedAt: time.Now().UTC(),
		}
		if err := e.store.PutIP(ctx, info); err != nil {
			e.logger.Warn("storing IP info", "ip", ip, "error", err)
			continue
		}

		if err := e.store.Remove(ctx, ip); err != nil {
			e.logger.Warn("removing from IP queue", "ip", ip, "error", err)
		}

		// Enqueue prefix if unknown
		if dns.BGPPrefix != "" {
			net, err := e.store.GetNetwork(ctx, dns.BGPPrefix)
			if err != nil {
				e.logger.Warn("checking network", "prefix", dns.BGPPrefix, "error", err)
			} else if net == nil {
				if err := e.store.EnqueuePrefix(ctx, dns.BGPPrefix); err != nil {
					e.logger.Warn("enqueueing prefix", "prefix", dns.BGPPrefix, "error", err)
				} else {
					newPrefixes = true
				}
			}
		}

		processed++
	}

	return processed, newPrefixes, nil
}

// PrefixEnricher processes the prefix queue: ipapi.is lookups, writes
// network_enrichment, backfills provider on ip_dns rows.
type PrefixEnricher struct {
	store   *SQLiteStore
	lookup  NetworkLookup
	limiter *RateLimiter
	logger  *slog.Logger
}

// NewPrefixEnricher creates a prefix enricher.
func NewPrefixEnricher(store *SQLiteStore, lookup NetworkLookup, limiter *RateLimiter, logger *slog.Logger) *PrefixEnricher {
	return &PrefixEnricher{store: store, lookup: lookup, limiter: limiter, logger: logger}
}

// ProcessBatch fetches up to batchSize prefixes and enriches them.
// Returns the number processed and whether the rate limit was hit.
func (e *PrefixEnricher) ProcessBatch(ctx context.Context, batchSize int) (processed int, rateLimited bool, err error) {
	prefixes, err := e.store.FetchPrefixBatch(ctx, batchSize)
	if err != nil {
		return 0, false, err
	}

	for _, prefix := range prefixes {
		// Already enriched? remove and skip
		existing, err := e.store.GetNetwork(ctx, prefix)
		if err != nil {
			e.logger.Warn("checking existing network", "prefix", prefix, "error", err)
			continue
		}
		if existing != nil {
			e.store.RemovePrefix(ctx, prefix)
			processed++
			continue
		}

		// Check rate limit
		if !e.limiter.TryAcquire() {
			e.logger.Info("daily API limit reached", "remaining", e.limiter.Remaining())
			return processed, true, nil
		}

		// Pick a representative IP for this prefix
		ip, err := e.store.PickIPForPrefix(ctx, prefix)
		if err != nil || ip == "" {
			e.logger.Warn("no IP for prefix", "prefix", prefix, "error", err)
			e.store.RemovePrefix(ctx, prefix)
			processed++
			continue
		}

		// API lookup
		apiResult, err := e.lookup.Lookup(ctx, ip)
		if err != nil {
			e.logger.Warn("ipapi.is lookup failed", "ip", ip, "prefix", prefix, "error", err)
			continue
		}

		// Resolve provider: tier 2 (brand alias) then tier 3 (passthrough)
		provider := MatchBrandAlias(apiResult)
		if provider == "" && apiResult.Datacenter != "" {
			provider = apiResult.Datacenter
		}

		// Use the most specific prefix across both sources. In BGP the
		// longest match determines actual routing and gives the most
		// precise grouping.
		canonical := moreSpecificPrefix(prefix, apiResult.BGPPrefix)

		// If the API returned a more specific prefix, update ip_dns
		// so the LEFT JOIN stays consistent.
		if canonical != prefix {
			if err := e.store.UpdateBGPPrefix(ctx, prefix, canonical); err != nil {
				e.logger.Warn("updating bgp_prefix", "from", prefix, "to", canonical, "error", err)
			}
		}

		netInfo := &NetworkInfo{
			BGPPrefix:    canonical,
			ASN:          apiResult.ASN,
			ASNOrg:       apiResult.ASNOrg,
			ISP:          apiResult.ISP,
			CompanyType:  apiResult.CompanyType,
			IsDatacenter: apiResult.IsDatacenter,
			Datacenter:   apiResult.Datacenter,
			Provider:     provider,
			City:         apiResult.City,
			Region:       apiResult.Region,
			Country:      apiResult.Country,
			Latitude:     apiResult.Latitude,
			Longitude:    apiResult.Longitude,
			EnrichedAt:   time.Now().UTC(),
			Source:       "ipapi.is",
		}

		if err := e.store.PutNetwork(ctx, netInfo); err != nil {
			e.logger.Warn("storing network info", "prefix", canonical, "error", err)
			continue
		}

		// Backfill provider on ip_dns rows where provider is not yet set
		if provider != "" {
			if err := e.store.BackfillProvider(ctx, canonical, provider); err != nil {
				e.logger.Warn("backfilling provider", "prefix", canonical, "error", err)
			}
			// Also backfill the Cymru prefix if it differs from the API prefix
			if prefix != canonical {
				e.store.BackfillProvider(ctx, prefix, provider)
			}
		}

		if err := e.store.RemovePrefix(ctx, prefix); err != nil {
			e.logger.Warn("removing from prefix queue", "prefix", prefix, "error", err)
		}

		processed++
	}

	return processed, false, nil
}
