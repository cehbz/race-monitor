package enrichment

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// Real ipapi.is response for the Ultra.cc IP from the user's sample.
const sampleIPAPIResponse = `{
  "ip": "216.163.184.16",
  "rir": "RIPE",
  "is_bogon": false,
  "is_mobile": false,
  "is_satellite": false,
  "is_crawler": false,
  "is_datacenter": true,
  "is_tor": false,
  "is_proxy": false,
  "is_vpn": false,
  "is_abuser": false,
  "datacenter": {
    "datacenter": "SlashN Services Pte. Ltd.",
    "domain": "slashn.com",
    "network": "216.163.184.0 - 216.163.187.255"
  },
  "company": {
    "name": "SlashN Services Pte. Ltd.",
    "abuser_score": "0.001 (Low)",
    "domain": "slashn.com",
    "type": "hosting",
    "network": "216.163.184.0 - 216.163.187.255",
    "whois": "https://api.ipapi.is/?whois=216.163.184.0"
  },
  "abuse": {
    "name": "Ante Blaskovic",
    "address": "10 ANSON ROAD, Singapore",
    "email": "abuse@usbx.me",
    "phone": "+385953539539"
  },
  "asn": {
    "asn": 208959,
    "abuser_score": "0.0053 (Low)",
    "route": "216.163.184.0/24",
    "descr": "SG-SLASHN, SG",
    "country": "sg",
    "active": true,
    "org": "SlashN Services Pte. Ltd.",
    "domain": "slashn.com",
    "abuse": "abuse@usbx.me",
    "type": "hosting",
    "created": "2019-05-06",
    "updated": "2026-01-19",
    "rir": "RIPE",
    "whois": "https://api.ipapi.is/?whois=AS208959"
  },
  "location": {
    "is_eu_member": true,
    "calling_code": "31",
    "currency_code": "EUR",
    "continent": "EU",
    "country": "The Netherlands",
    "country_code": "NL",
    "state": "North Holland",
    "city": "Amsterdam",
    "latitude": 52.3785,
    "longitude": 4.89998,
    "zip": "1384",
    "timezone": "Europe/Brussels",
    "local_time": "2026-02-21T13:04:19+01:00",
    "local_time_unix": 1771675459,
    "is_dst": false
  },
  "elapsed_ms": 0.72
}`

func TestParseIPAPIResponse(t *testing.T) {
	result, err := parseIPAPIResponse([]byte(sampleIPAPIResponse))
	if err != nil {
		t.Fatalf("parseIPAPIResponse: %v", err)
	}

	if result.ASN != 208959 {
		t.Errorf("ASN = %d, want 208959", result.ASN)
	}
	if result.ASNOrg != "SlashN Services Pte. Ltd." {
		t.Errorf("ASNOrg = %q", result.ASNOrg)
	}
	if result.BGPPrefix != "216.163.184.0/24" {
		t.Errorf("BGPPrefix = %q", result.BGPPrefix)
	}
	if result.ISP != "SlashN Services Pte. Ltd." {
		t.Errorf("ISP = %q", result.ISP)
	}
	if result.CompanyType != "hosting" {
		t.Errorf("CompanyType = %q", result.CompanyType)
	}
	if result.CompanyDomain != "slashn.com" {
		t.Errorf("CompanyDomain = %q", result.CompanyDomain)
	}
	if !result.IsDatacenter {
		t.Error("IsDatacenter = false, want true")
	}
	if result.Datacenter != "SlashN Services Pte. Ltd." {
		t.Errorf("Datacenter = %q", result.Datacenter)
	}
	if result.DCDomain != "slashn.com" {
		t.Errorf("DCDomain = %q", result.DCDomain)
	}
	if result.AbuseEmail != "abuse@usbx.me" {
		t.Errorf("AbuseEmail = %q", result.AbuseEmail)
	}
	if result.City != "Amsterdam" {
		t.Errorf("City = %q", result.City)
	}
	if result.Region != "North Holland" {
		t.Errorf("Region = %q", result.Region)
	}
	if result.Country != "NL" {
		t.Errorf("Country = %q", result.Country)
	}
	if result.Latitude < 52.37 || result.Latitude > 52.38 {
		t.Errorf("Latitude = %f", result.Latitude)
	}
}

func TestParseIPAPIResponseResidential(t *testing.T) {
	// Minimal residential IP response (no datacenter/abuse objects)
	data := `{
		"is_datacenter": false,
		"company": {"name": "Comcast", "domain": "comcast.com", "type": "isp"},
		"asn": {"asn": 7922, "route": "73.0.0.0/8", "org": "Comcast Cable"},
		"location": {"city": "Denver", "state": "Colorado", "country_code": "US",
		             "latitude": 39.74, "longitude": -104.99}
	}`

	result, err := parseIPAPIResponse([]byte(data))
	if err != nil {
		t.Fatalf("parseIPAPIResponse: %v", err)
	}

	if result.IsDatacenter {
		t.Error("IsDatacenter = true, want false")
	}
	if result.Datacenter != "" {
		t.Errorf("Datacenter = %q, want empty", result.Datacenter)
	}
	if result.ISP != "Comcast" {
		t.Errorf("ISP = %q", result.ISP)
	}
	if result.CompanyType != "isp" {
		t.Errorf("CompanyType = %q", result.CompanyType)
	}
}

func TestIPAPIClientWithTestServer(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("q") != "216.163.184.16" {
			t.Errorf("unexpected query IP: %s", r.URL.Query().Get("q"))
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(sampleIPAPIResponse))
	}))
	defer server.Close()

	client := &IPAPIClient{
		httpClient: server.Client(),
		baseURL:    server.URL,
	}

	result, err := client.Lookup(context.Background(), "216.163.184.16")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if result.ASN != 208959 {
		t.Errorf("ASN = %d, want 208959", result.ASN)
	}
	if result.City != "Amsterdam" {
		t.Errorf("City = %q, want Amsterdam", result.City)
	}
}

func TestIPAPIClientErrorResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
		w.Write([]byte("rate limited"))
	}))
	defer server.Close()

	client := &IPAPIClient{
		httpClient: server.Client(),
		baseURL:    server.URL,
	}

	_, err := client.Lookup(context.Background(), "1.2.3.4")
	if err == nil {
		t.Fatal("expected error on 429 response")
	}
}

// Integration test: full pipeline from ipapi.is response → provider resolution
func TestEndToEndProviderResolution(t *testing.T) {
	result, err := parseIPAPIResponse([]byte(sampleIPAPIResponse))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	// No rDNS that matches a pattern — should fall through to brand alias map
	provider := ResolveProvider("generic.host.slashn.com", result)
	if provider != "Ultra.cc" {
		t.Errorf("ResolveProvider = %q, want %q", provider, "Ultra.cc")
	}
}
