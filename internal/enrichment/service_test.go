package enrichment

import (
	"context"
	"log/slog"
	"os"
	"testing"
)

// fakeDNSResolver returns canned DNS results.
type fakeDNSResolver struct {
	results map[string]*DNSResult
}

func (f *fakeDNSResolver) Resolve(_ context.Context, ip string) (*DNSResult, error) {
	if r, ok := f.results[ip]; ok {
		return r, nil
	}
	return &DNSResult{}, nil
}

// fakeNetworkLookup returns canned API results.
type fakeNetworkLookup struct {
	results map[string]*APIResult
}

func (f *fakeNetworkLookup) Lookup(_ context.Context, ip string) (*APIResult, error) {
	if r, ok := f.results[ip]; ok {
		return r, nil
	}
	return &APIResult{}, nil
}

var testLogger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

func TestIPEnricherProcessBatch(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	// Seed the IP queue
	store.db.Exec(`INSERT INTO enrichment_queue (ip, queued_at) VALUES ('1.2.3.4', '2026-01-01')`)
	store.db.Exec(`INSERT INTO enrichment_queue (ip, queued_at) VALUES ('5.6.7.8', '2026-01-01')`)

	resolver := &fakeDNSResolver{
		results: map[string]*DNSResult{
			"1.2.3.4": {RDNS: "box.feral.io", ASN: 200052, BGPPrefix: "1.2.3.0/24", Country: "GB"},
			"5.6.7.8": {RDNS: "host.example.com", ASN: 12345, BGPPrefix: "5.6.7.0/24", Country: "US"},
		},
	}

	enricher := NewIPEnricher(store, resolver, testLogger)
	processed, newPrefixes, err := enricher.ProcessBatch(ctx, 10)
	if err != nil {
		t.Fatalf("ProcessBatch: %v", err)
	}
	if processed != 2 {
		t.Errorf("processed = %d, want 2", processed)
	}
	if !newPrefixes {
		t.Error("newPrefixes = false, want true")
	}

	// Check ip_dns was written
	ip1, _ := store.GetIP(ctx, "1.2.3.4")
	if ip1 == nil {
		t.Fatal("ip_dns not found for 1.2.3.4")
	}
	if ip1.RDNS != "box.feral.io" {
		t.Errorf("RDNS = %q, want %q", ip1.RDNS, "box.feral.io")
	}
	if ip1.Provider != "Feral" {
		t.Errorf("Provider = %q, want %q (tier 1 rDNS match)", ip1.Provider, "Feral")
	}
	if ip1.BGPPrefix != "1.2.3.0/24" {
		t.Errorf("BGPPrefix = %q, want %q", ip1.BGPPrefix, "1.2.3.0/24")
	}

	// Check IP queue was drained
	remaining, _ := store.FetchBatch(ctx, 10)
	if len(remaining) != 0 {
		t.Errorf("IP queue still has %d items", len(remaining))
	}

	// Check prefix queue was populated
	prefixes, _ := store.FetchPrefixBatch(ctx, 10)
	if len(prefixes) != 2 {
		t.Errorf("prefix queue has %d items, want 2", len(prefixes))
	}
}

func TestIPEnricherSkipsAlreadyEnriched(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	// Pre-populate ip_dns
	store.PutIP(ctx, &IPInfo{IP: "1.2.3.4", RDNS: "old.host.com", BGPPrefix: "1.2.3.0/24"})
	// Add to queue
	store.db.Exec(`INSERT INTO enrichment_queue (ip, queued_at) VALUES ('1.2.3.4', '2026-01-01')`)

	resolver := &fakeDNSResolver{results: map[string]*DNSResult{}}
	enricher := NewIPEnricher(store, resolver, testLogger)
	processed, _, _ := enricher.ProcessBatch(ctx, 10)

	if processed != 1 {
		t.Errorf("processed = %d, want 1", processed)
	}

	// Should not have been re-resolved
	ip, _ := store.GetIP(ctx, "1.2.3.4")
	if ip.RDNS != "old.host.com" {
		t.Errorf("RDNS = %q, want %q (should not be overwritten)", ip.RDNS, "old.host.com")
	}
}

func TestPrefixEnricherProcessBatch(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	// Seed: ip_dns row referencing a prefix, prefix in queue
	store.PutIP(ctx, &IPInfo{IP: "216.163.184.16", BGPPrefix: "216.163.184.0/24"})
	store.EnqueuePrefix(ctx, "216.163.184.0/24")

	lookup := &fakeNetworkLookup{
		results: map[string]*APIResult{
			"216.163.184.16": {
				ASN: 208959, ASNOrg: "SlashN Services Pte. Ltd.",
				BGPPrefix: "216.163.184.0/24", ISP: "SlashN Services Pte. Ltd.",
				CompanyType: "hosting", CompanyDomain: "slashn.com",
				IsDatacenter: true, Datacenter: "SlashN Services Pte. Ltd.",
				DCDomain: "slashn.com", AbuseEmail: "abuse@usbx.me",
				City: "Amsterdam", Region: "North Holland", Country: "NL",
				Latitude: 52.3785, Longitude: 4.89998,
			},
		},
	}

	limiter := NewRateLimiter(900)
	enricher := NewPrefixEnricher(store, lookup, limiter, testLogger)
	processed, rateLimited, err := enricher.ProcessBatch(ctx, 10)
	if err != nil {
		t.Fatalf("ProcessBatch: %v", err)
	}
	if processed != 1 {
		t.Errorf("processed = %d, want 1", processed)
	}
	if rateLimited {
		t.Error("rateLimited = true, want false")
	}

	// Check network_enrichment was written
	net, _ := store.GetNetwork(ctx, "216.163.184.0/24")
	if net == nil {
		t.Fatal("network_enrichment not found")
	}
	if net.Provider != "Ultra.cc" {
		t.Errorf("Provider = %q, want %q", net.Provider, "Ultra.cc")
	}
	if net.City != "Amsterdam" {
		t.Errorf("City = %q", net.City)
	}
	if !net.IsDatacenter {
		t.Error("IsDatacenter = false")
	}

	// Check backfill: ip_dns row should now have provider set
	ip, _ := store.GetIP(ctx, "216.163.184.16")
	if ip.Provider != "Ultra.cc" {
		t.Errorf("ip_dns provider after backfill = %q, want %q", ip.Provider, "Ultra.cc")
	}

	// Check prefix queue drained
	prefixes, _ := store.FetchPrefixBatch(ctx, 10)
	if len(prefixes) != 0 {
		t.Errorf("prefix queue has %d items", len(prefixes))
	}
}

func TestPrefixEnricherRateLimited(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	store.PutIP(ctx, &IPInfo{IP: "1.1.1.1", BGPPrefix: "1.1.1.0/24"})
	store.PutIP(ctx, &IPInfo{IP: "2.2.2.2", BGPPrefix: "2.2.2.0/24"})
	store.EnqueuePrefix(ctx, "1.1.1.0/24")
	store.EnqueuePrefix(ctx, "2.2.2.0/24")

	lookup := &fakeNetworkLookup{
		results: map[string]*APIResult{
			"1.1.1.1": {ASN: 13335, BGPPrefix: "1.1.1.0/24", ISP: "Cloudflare"},
			"2.2.2.2": {ASN: 3215, BGPPrefix: "2.2.2.0/24", ISP: "Orange"},
		},
	}

	// Only 1 API call allowed
	limiter := NewRateLimiter(1)
	enricher := NewPrefixEnricher(store, lookup, limiter, testLogger)
	processed, rateLimited, err := enricher.ProcessBatch(ctx, 10)
	if err != nil {
		t.Fatalf("ProcessBatch: %v", err)
	}
	if processed != 1 {
		t.Errorf("processed = %d, want 1", processed)
	}
	if !rateLimited {
		t.Error("rateLimited = false, want true")
	}

	// One prefix should remain in queue
	remaining, _ := store.FetchPrefixBatch(ctx, 10)
	if len(remaining) != 1 {
		t.Errorf("prefix queue has %d items, want 1", len(remaining))
	}
}

func TestMoreSpecificPrefix(t *testing.T) {
	tests := []struct {
		name  string
		cymru string
		api   string
		want  string
	}{
		{"api more specific", "115.69.32.0/19", "115.69.36.0/24", "115.69.36.0/24"},
		{"cymru more specific", "115.69.36.0/24", "115.69.32.0/19", "115.69.36.0/24"},
		{"equal", "10.0.0.0/24", "10.0.0.0/24", "10.0.0.0/24"},
		{"api empty", "10.0.0.0/24", "", "10.0.0.0/24"},
		{"api malformed", "10.0.0.0/24", "garbage", "10.0.0.0/24"},
		{"cymru malformed", "garbage", "10.0.0.0/24", "10.0.0.0/24"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := moreSpecificPrefix(tt.cymru, tt.api)
			if got != tt.want {
				t.Errorf("moreSpecificPrefix(%q, %q) = %q, want %q", tt.cymru, tt.api, got, tt.want)
			}
		})
	}
}

func TestPrefixEnricherPrefixMismatch(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	// Cymru returned /24, API will return /19
	store.PutIP(ctx, &IPInfo{IP: "115.69.36.55", BGPPrefix: "115.69.36.0/24"})
	store.EnqueuePrefix(ctx, "115.69.36.0/24")

	lookup := &fakeNetworkLookup{
		results: map[string]*APIResult{
			"115.69.36.55": {
				ASN: 18390, ASNOrg: "Spintel Pty Ltd",
				BGPPrefix: "115.69.32.0/19", ISP: "Spintel Pty Ltd",
				CompanyType: "isp",
				City:        "Sydney", Country: "AU",
			},
		},
	}

	limiter := NewRateLimiter(900)
	enricher := NewPrefixEnricher(store, lookup, limiter, testLogger)
	processed, _, err := enricher.ProcessBatch(ctx, 10)
	if err != nil {
		t.Fatalf("ProcessBatch: %v", err)
	}
	if processed != 1 {
		t.Errorf("processed = %d, want 1", processed)
	}

	// Cymru /24 is more specific — network_enrichment should be keyed by it
	net, _ := store.GetNetwork(ctx, "115.69.36.0/24")
	if net == nil {
		t.Fatal("network_enrichment not found under Cymru /24 prefix")
	}
	if net.ISP != "Spintel Pty Ltd" {
		t.Errorf("ISP = %q", net.ISP)
	}

	// ip_dns.bgp_prefix should still be the Cymru /24 (unchanged)
	ip, _ := store.GetIP(ctx, "115.69.36.55")
	if ip.BGPPrefix != "115.69.36.0/24" {
		t.Errorf("ip_dns.bgp_prefix = %q, want %q", ip.BGPPrefix, "115.69.36.0/24")
	}

	// Should NOT exist under the less-specific API prefix
	netWrong, _ := store.GetNetwork(ctx, "115.69.32.0/19")
	if netWrong != nil {
		t.Error("network_enrichment should NOT exist under the API /19 prefix")
	}
}

func TestRateLimiterDailyReset(t *testing.T) {
	limiter := NewRateLimiter(2)

	if !limiter.TryAcquire() {
		t.Error("first acquire should succeed")
	}
	if !limiter.TryAcquire() {
		t.Error("second acquire should succeed")
	}
	if limiter.TryAcquire() {
		t.Error("third acquire should fail (limit=2)")
	}

	if limiter.Remaining() != 0 {
		t.Errorf("Remaining = %d, want 0", limiter.Remaining())
	}
}
