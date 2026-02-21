package enrichment

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

// SQLiteStore implements IPStore, NetworkStore, IPQueue, and PrefixQueue
// against the enrichment tables in the race-monitor SQLite database.
//
// These tables are created with CREATE TABLE IF NOT EXISTS and are not part
// of the Go daemon's versioned schema — they survive schema bumps.
type SQLiteStore struct {
	db *sql.DB
}

// NewSQLiteStore opens a SQLite connection and ensures enrichment tables exist.
func NewSQLiteStore(dbPath string) (*SQLiteStore, error) {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("opening database: %w", err)
	}

	db.SetMaxOpenConns(1)

	if _, err := db.Exec("PRAGMA journal_mode=WAL"); err != nil {
		db.Close()
		return nil, fmt.Errorf("setting WAL mode: %w", err)
	}
	if _, err := db.Exec("PRAGMA busy_timeout=5000"); err != nil {
		db.Close()
		return nil, fmt.Errorf("setting busy timeout: %w", err)
	}

	s := &SQLiteStore{db: db}
	if err := s.createTables(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *SQLiteStore) createTables() error {
	schema := `
	CREATE TABLE IF NOT EXISTS enrichment_queue (
		ip        TEXT PRIMARY KEY,
		queued_at TEXT NOT NULL
	);

	CREATE TABLE IF NOT EXISTS ip_dns (
		ip          TEXT PRIMARY KEY,
		rdns        TEXT,
		bgp_prefix  TEXT,
		provider    TEXT,
		enriched_at TEXT
	);

	CREATE TABLE IF NOT EXISTS prefix_queue (
		bgp_prefix TEXT PRIMARY KEY,
		queued_at  TEXT NOT NULL
	);

	CREATE TABLE IF NOT EXISTS network_enrichment (
		bgp_prefix    TEXT PRIMARY KEY,
		asn           INTEGER,
		asn_org       TEXT,
		isp           TEXT,
		company_type  TEXT,
		is_datacenter INTEGER DEFAULT 0,
		datacenter    TEXT,
		provider      TEXT,
		city          TEXT,
		region        TEXT,
		country       TEXT,
		latitude      REAL,
		longitude     REAL,
		enriched_at   TEXT,
		source        TEXT
	);

	CREATE INDEX IF NOT EXISTS idx_ip_dns_prefix ON ip_dns(bgp_prefix);
	CREATE INDEX IF NOT EXISTS idx_enrichment_prefix ON network_enrichment(bgp_prefix);
	`
	if _, err := s.db.Exec(schema); err != nil {
		return fmt.Errorf("creating enrichment tables: %w", err)
	}
	return nil
}

// Close closes the database connection.
func (s *SQLiteStore) Close() error {
	return s.db.Close()
}

// formatTS formats a time as RFC 3339 with millisecond precision.
func formatTS(t time.Time) string {
	return t.UTC().Format("2006-01-02T15:04:05.000Z")
}

// Backfill enqueues all distinct IPs from the connections table that aren't
// already in ip_dns. Used for bootstrapping existing databases.
func (s *SQLiteStore) Backfill(ctx context.Context) (int, error) {
	result, err := s.db.ExecContext(ctx,
		`INSERT OR IGNORE INTO enrichment_queue (ip, queued_at)
		SELECT DISTINCT c.ip, datetime('now')
		FROM connections c
		WHERE c.ip IS NOT NULL AND c.ip != ''
		AND c.ip NOT IN (SELECT ip FROM ip_dns)`)
	if err != nil {
		return 0, fmt.Errorf("backfill: %w", err)
	}
	n, _ := result.RowsAffected()
	return int(n), nil
}

// --- IPStore ---

func (s *SQLiteStore) GetIP(ctx context.Context, ip string) (*IPInfo, error) {
	var info IPInfo
	var enrichedAt sql.NullString
	err := s.db.QueryRowContext(ctx,
		`SELECT ip, rdns, bgp_prefix, provider, enriched_at FROM ip_dns WHERE ip = ?`, ip,
	).Scan(&info.IP, &info.RDNS, &info.BGPPrefix, &info.Provider, &enrichedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("getting IP %s: %w", ip, err)
	}
	return &info, nil
}

func (s *SQLiteStore) PutIP(ctx context.Context, info *IPInfo) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO ip_dns (ip, rdns, bgp_prefix, provider, enriched_at)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(ip) DO UPDATE SET
			rdns = excluded.rdns,
			bgp_prefix = excluded.bgp_prefix,
			provider = excluded.provider,
			enriched_at = excluded.enriched_at`,
		info.IP, info.RDNS, info.BGPPrefix, info.Provider, formatTS(time.Now()))
	return err
}

func (s *SQLiteStore) BackfillProvider(ctx context.Context, bgpPrefix, provider string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE ip_dns SET provider = ? WHERE bgp_prefix = ? AND (provider IS NULL OR provider = '')`,
		provider, bgpPrefix)
	return err
}

// --- NetworkStore ---

func (s *SQLiteStore) GetNetwork(ctx context.Context, prefix string) (*NetworkInfo, error) {
	var info NetworkInfo
	var isdc int
	err := s.db.QueryRowContext(ctx,
		`SELECT bgp_prefix, asn, asn_org, isp, company_type, is_datacenter,
		        datacenter, provider, city, region, country, latitude, longitude, source
		FROM network_enrichment WHERE bgp_prefix = ?`, prefix,
	).Scan(&info.BGPPrefix, &info.ASN, &info.ASNOrg, &info.ISP, &info.CompanyType,
		&isdc, &info.Datacenter, &info.Provider, &info.City, &info.Region,
		&info.Country, &info.Latitude, &info.Longitude, &info.Source)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("getting network %s: %w", prefix, err)
	}
	info.IsDatacenter = isdc != 0
	return &info, nil
}

func (s *SQLiteStore) PutNetwork(ctx context.Context, info *NetworkInfo) error {
	isdc := 0
	if info.IsDatacenter {
		isdc = 1
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO network_enrichment
			(bgp_prefix, asn, asn_org, isp, company_type, is_datacenter,
			 datacenter, provider, city, region, country, latitude, longitude,
			 enriched_at, source)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(bgp_prefix) DO UPDATE SET
			asn = excluded.asn, asn_org = excluded.asn_org,
			isp = excluded.isp, company_type = excluded.company_type,
			is_datacenter = excluded.is_datacenter, datacenter = excluded.datacenter,
			provider = excluded.provider, city = excluded.city, region = excluded.region,
			country = excluded.country, latitude = excluded.latitude,
			longitude = excluded.longitude, enriched_at = excluded.enriched_at,
			source = excluded.source`,
		info.BGPPrefix, info.ASN, info.ASNOrg, info.ISP, info.CompanyType,
		isdc, info.Datacenter, info.Provider, info.City, info.Region,
		info.Country, info.Latitude, info.Longitude, formatTS(time.Now()), info.Source)
	return err
}

func (s *SQLiteStore) PickIPForPrefix(ctx context.Context, prefix string) (string, error) {
	var ip string
	err := s.db.QueryRowContext(ctx,
		`SELECT ip FROM ip_dns WHERE bgp_prefix = ? LIMIT 1`, prefix,
	).Scan(&ip)
	if err == sql.ErrNoRows {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("picking IP for prefix %s: %w", prefix, err)
	}
	return ip, nil
}

// --- IPQueue (enrichment_queue) ---

func (s *SQLiteStore) FetchBatch(ctx context.Context, limit int) ([]string, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT ip FROM enrichment_queue ORDER BY queued_at LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("fetching IP queue: %w", err)
	}
	defer rows.Close()

	var ips []string
	for rows.Next() {
		var ip string
		if err := rows.Scan(&ip); err != nil {
			return nil, err
		}
		ips = append(ips, ip)
	}
	return ips, rows.Err()
}

func (s *SQLiteStore) Remove(ctx context.Context, ip string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM enrichment_queue WHERE ip = ?`, ip)
	return err
}

// --- PrefixQueue ---

func (s *SQLiteStore) EnqueuePrefix(ctx context.Context, prefix string) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT OR IGNORE INTO prefix_queue (bgp_prefix, queued_at) VALUES (?, ?)`,
		prefix, formatTS(time.Now()))
	return err
}

func (s *SQLiteStore) FetchPrefixBatch(ctx context.Context, limit int) ([]string, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT bgp_prefix FROM prefix_queue ORDER BY queued_at LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("fetching prefix queue: %w", err)
	}
	defer rows.Close()

	var prefixes []string
	for rows.Next() {
		var p string
		if err := rows.Scan(&p); err != nil {
			return nil, err
		}
		prefixes = append(prefixes, p)
	}
	return prefixes, rows.Err()
}

func (s *SQLiteStore) RemovePrefix(ctx context.Context, prefix string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM prefix_queue WHERE bgp_prefix = ?`, prefix)
	return err
}
