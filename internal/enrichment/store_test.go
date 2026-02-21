package enrichment

import (
	"context"
	"testing"
	"time"
)

func newTestStore(t *testing.T) *SQLiteStore {
	t.Helper()
	s, err := NewSQLiteStore(":memory:")
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// --- IPStore ---

func TestPutAndGetIP(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	info := &IPInfo{
		IP:         "1.2.3.4",
		RDNS:       "host.example.com",
		BGPPrefix:  "1.2.3.0/24",
		Provider:   "Feral",
		EnrichedAt: time.Now().UTC().Truncate(time.Second),
	}

	if err := s.PutIP(ctx, info); err != nil {
		t.Fatalf("PutIP: %v", err)
	}

	got, err := s.GetIP(ctx, "1.2.3.4")
	if err != nil {
		t.Fatalf("GetIP: %v", err)
	}
	if got == nil {
		t.Fatal("GetIP returned nil")
	}
	if got.RDNS != "host.example.com" {
		t.Errorf("RDNS = %q, want %q", got.RDNS, "host.example.com")
	}
	if got.BGPPrefix != "1.2.3.0/24" {
		t.Errorf("BGPPrefix = %q, want %q", got.BGPPrefix, "1.2.3.0/24")
	}
	if got.Provider != "Feral" {
		t.Errorf("Provider = %q, want %q", got.Provider, "Feral")
	}
}

func TestGetIPNotFound(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	got, err := s.GetIP(ctx, "9.9.9.9")
	if err != nil {
		t.Fatalf("GetIP: %v", err)
	}
	if got != nil {
		t.Errorf("expected nil, got %+v", got)
	}
}

func TestPutIPUpsert(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	info := &IPInfo{IP: "1.2.3.4", RDNS: "old.host.com", BGPPrefix: "1.2.3.0/24"}
	if err := s.PutIP(ctx, info); err != nil {
		t.Fatalf("PutIP: %v", err)
	}

	info.RDNS = "new.host.com"
	if err := s.PutIP(ctx, info); err != nil {
		t.Fatalf("PutIP upsert: %v", err)
	}

	got, _ := s.GetIP(ctx, "1.2.3.4")
	if got.RDNS != "new.host.com" {
		t.Errorf("RDNS after upsert = %q, want %q", got.RDNS, "new.host.com")
	}
}

func TestBackfillProvider(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	// Two IPs in same prefix, no provider set
	s.PutIP(ctx, &IPInfo{IP: "1.2.3.4", BGPPrefix: "1.2.3.0/24"})
	s.PutIP(ctx, &IPInfo{IP: "1.2.3.5", BGPPrefix: "1.2.3.0/24"})
	// One IP with provider already set — should not be overwritten
	s.PutIP(ctx, &IPInfo{IP: "1.2.3.6", BGPPrefix: "1.2.3.0/24", Provider: "Existing"})
	// Different prefix — should not be touched
	s.PutIP(ctx, &IPInfo{IP: "5.6.7.8", BGPPrefix: "5.6.7.0/24"})

	if err := s.BackfillProvider(ctx, "1.2.3.0/24", "Ultra.cc"); err != nil {
		t.Fatalf("BackfillProvider: %v", err)
	}

	got4, _ := s.GetIP(ctx, "1.2.3.4")
	if got4.Provider != "Ultra.cc" {
		t.Errorf("1.2.3.4 provider = %q, want %q", got4.Provider, "Ultra.cc")
	}

	got5, _ := s.GetIP(ctx, "1.2.3.5")
	if got5.Provider != "Ultra.cc" {
		t.Errorf("1.2.3.5 provider = %q, want %q", got5.Provider, "Ultra.cc")
	}

	got6, _ := s.GetIP(ctx, "1.2.3.6")
	if got6.Provider != "Existing" {
		t.Errorf("1.2.3.6 provider = %q, want %q (should not be overwritten)", got6.Provider, "Existing")
	}

	got8, _ := s.GetIP(ctx, "5.6.7.8")
	if got8.Provider != "" {
		t.Errorf("5.6.7.8 provider = %q, want empty (different prefix)", got8.Provider)
	}
}

// --- NetworkStore ---

func TestPutAndGetNetwork(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	info := &NetworkInfo{
		BGPPrefix:    "185.21.216.0/22",
		ASN:          208959,
		ASNOrg:       "SlashN Services",
		ISP:          "SlashN Services Pte. Ltd.",
		CompanyType:  "hosting",
		IsDatacenter: true,
		Datacenter:   "SlashN Services Pte. Ltd.",
		Provider:     "Ultra.cc",
		City:         "Amsterdam",
		Region:       "North Holland",
		Country:      "NL",
		Latitude:     52.3785,
		Longitude:    4.89998,
		Source:       "ipapi.is",
	}

	if err := s.PutNetwork(ctx, info); err != nil {
		t.Fatalf("PutNetwork: %v", err)
	}

	got, err := s.GetNetwork(ctx, "185.21.216.0/22")
	if err != nil {
		t.Fatalf("GetNetwork: %v", err)
	}
	if got == nil {
		t.Fatal("GetNetwork returned nil")
	}
	if got.ASN != 208959 {
		t.Errorf("ASN = %d, want %d", got.ASN, 208959)
	}
	if got.Provider != "Ultra.cc" {
		t.Errorf("Provider = %q, want %q", got.Provider, "Ultra.cc")
	}
	if got.City != "Amsterdam" {
		t.Errorf("City = %q, want %q", got.City, "Amsterdam")
	}
	if !got.IsDatacenter {
		t.Error("IsDatacenter = false, want true")
	}
}

func TestGetNetworkNotFound(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	got, err := s.GetNetwork(ctx, "99.99.99.0/24")
	if err != nil {
		t.Fatalf("GetNetwork: %v", err)
	}
	if got != nil {
		t.Errorf("expected nil, got %+v", got)
	}
}

func TestPickIPForPrefix(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	s.PutIP(ctx, &IPInfo{IP: "1.2.3.4", BGPPrefix: "1.2.3.0/24"})
	s.PutIP(ctx, &IPInfo{IP: "1.2.3.5", BGPPrefix: "1.2.3.0/24"})

	ip, err := s.PickIPForPrefix(ctx, "1.2.3.0/24")
	if err != nil {
		t.Fatalf("PickIPForPrefix: %v", err)
	}
	if ip != "1.2.3.4" && ip != "1.2.3.5" {
		t.Errorf("PickIPForPrefix = %q, want 1.2.3.4 or 1.2.3.5", ip)
	}
}

func TestPickIPForPrefixNotFound(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	ip, err := s.PickIPForPrefix(ctx, "99.99.99.0/24")
	if err != nil {
		t.Fatalf("PickIPForPrefix: %v", err)
	}
	if ip != "" {
		t.Errorf("PickIPForPrefix = %q, want empty", ip)
	}
}

// --- IPQueue ---

func TestIPQueueFetchAndRemove(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	// Populate queue via direct SQL (simulating what the Go daemon does)
	s.db.Exec(`INSERT INTO enrichment_queue (ip, queued_at) VALUES ('1.1.1.1', '2026-01-01')`)
	s.db.Exec(`INSERT INTO enrichment_queue (ip, queued_at) VALUES ('2.2.2.2', '2026-01-01')`)
	s.db.Exec(`INSERT INTO enrichment_queue (ip, queued_at) VALUES ('3.3.3.3', '2026-01-01')`)

	ips, err := s.FetchBatch(ctx, 2)
	if err != nil {
		t.Fatalf("FetchBatch: %v", err)
	}
	if len(ips) != 2 {
		t.Fatalf("FetchBatch returned %d IPs, want 2", len(ips))
	}

	if err := s.Remove(ctx, ips[0]); err != nil {
		t.Fatalf("Remove: %v", err)
	}

	remaining, _ := s.FetchBatch(ctx, 10)
	if len(remaining) != 2 {
		t.Errorf("after Remove, FetchBatch returned %d IPs, want 2", len(remaining))
	}
}

func TestIPQueueEmpty(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	ips, err := s.FetchBatch(ctx, 10)
	if err != nil {
		t.Fatalf("FetchBatch: %v", err)
	}
	if len(ips) != 0 {
		t.Errorf("FetchBatch on empty queue returned %d IPs", len(ips))
	}
}

// --- PrefixQueue ---

func TestPrefixQueueEnqueueAndFetch(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	if err := s.EnqueuePrefix(ctx, "1.2.3.0/24"); err != nil {
		t.Fatalf("EnqueuePrefix: %v", err)
	}
	// Idempotent
	if err := s.EnqueuePrefix(ctx, "1.2.3.0/24"); err != nil {
		t.Fatalf("EnqueuePrefix duplicate: %v", err)
	}
	if err := s.EnqueuePrefix(ctx, "5.6.7.0/24"); err != nil {
		t.Fatalf("EnqueuePrefix: %v", err)
	}

	prefixes, err := s.FetchPrefixBatch(ctx, 10)
	if err != nil {
		t.Fatalf("FetchPrefixBatch: %v", err)
	}
	if len(prefixes) != 2 {
		t.Fatalf("FetchPrefixBatch returned %d, want 2", len(prefixes))
	}

	if err := s.RemovePrefix(ctx, "1.2.3.0/24"); err != nil {
		t.Fatalf("RemovePrefix: %v", err)
	}

	remaining, _ := s.FetchPrefixBatch(ctx, 10)
	if len(remaining) != 1 {
		t.Errorf("after RemovePrefix, got %d, want 1", len(remaining))
	}
}
