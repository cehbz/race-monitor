package enrichment

import "testing"

func TestMatchRDNS(t *testing.T) {
	tests := []struct {
		name     string
		rdns     string
		expected string
	}{
		{"feral.io subdomain", "box123.feral.io", "Feral"},
		{"feralhosting in hostname", "server.feralhosting.com", "Feral"},
		{"whatbox hostname", "lemon.whatbox.ca", "Whatbox"},
		{"bytesized hostname", "app.bytesized-hosting.com", "Bytesized"},
		{"seedboxes.cc", "vps.seedboxes.cc", "Seedboxes.cc"},
		{"ultraseedbox", "us123.ultraseedbox.com", "Ultra.cc"},
		{"ultra.cc direct", "box.ultra.cc", "Ultra.cc"},
		{"rapidseedbox", "rs.rapidseedbox.com", "RapidSeedbox"},
		{"seedhost", "sb1.seedhost.eu", "Seedhost.eu"},
		{"pulsedmedia", "dedi.pulsedmedia.com", "PulsedMedia"},
		{"hostingbydesign", "x.hostingbydesign.com", "HostingByDesign"},
		{"sbdx domain", "box.sbdx.io", "HostingByDesign"},
		{"leaseweb hostname", "hosted-by.leaseweb.com", "Leaseweb"},
		{"hostdzire hostname", "181.44.211.95.hosted.by.hostdzire.com", "Leaseweb"},
		{"hetzner hostname", "static.123.45.67.89.clients.your-server.hetzner.com", "Hetzner"},
		{"netcup hostname", "v2201234567890.netcup.net", "netcup"},
		{"hosthatch hostname", "vps.hosthatch.com", "HostHatch"},
		{"scaleway hostname", "abc.scaleway.com", "Scaleway"},
		{"ovh prefix", "vps-123.ovh.net", "OVH"},
		{"ovh suffix", "ns123.ip-1-2-3.ovh", "OVH"},
		{"no match", "server.example.com", ""},
		{"empty string", "", ""},
		{"generic hostname", "host-192-168-1-1.isp.net", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := MatchRDNS(tt.rdns)
			if got != tt.expected {
				t.Errorf("MatchRDNS(%q) = %q, want %q", tt.rdns, got, tt.expected)
			}
		})
	}
}

func TestMatchBrandAlias(t *testing.T) {
	tests := []struct {
		name     string
		result   *APIResult
		expected string
	}{
		{
			name:     "Ultra.cc via ASN",
			result:   &APIResult{ASN: 208959},
			expected: "Ultra.cc",
		},
		{
			name:     "Feral via ASN",
			result:   &APIResult{ASN: 200052},
			expected: "Feral",
		},
		{
			name:     "Ultra.cc via company domain",
			result:   &APIResult{CompanyDomain: "slashn.com"},
			expected: "Ultra.cc",
		},
		{
			name:     "Ultra.cc via abuse email",
			result:   &APIResult{AbuseEmail: "abuse@usbx.me"},
			expected: "Ultra.cc",
		},
		{
			name:     "Ultra.cc via datacenter domain",
			result:   &APIResult{DCDomain: "ultra.cc"},
			expected: "Ultra.cc",
		},
		{
			name:     "Feral via company domain",
			result:   &APIResult{CompanyDomain: "feral.io"},
			expected: "Feral",
		},
		{
			name:     "Whatbox via company domain",
			result:   &APIResult{CompanyDomain: "whatbox.ca"},
			expected: "Whatbox",
		},
		{
			name:     "Leaseweb via company domain",
			result:   &APIResult{CompanyDomain: "leaseweb.com"},
			expected: "Leaseweb",
		},
		{
			name:     "Hetzner via company domain",
			result:   &APIResult{CompanyDomain: "hetzner.com"},
			expected: "Hetzner",
		},
		{
			name:     "OVH via abuse email",
			result:   &APIResult{AbuseEmail: "abuse@ovh.net"},
			expected: "OVH",
		},
		{
			name:     "no match",
			result:   &APIResult{ASN: 99999, CompanyDomain: "random.com"},
			expected: "",
		},
		{
			name:     "nil result",
			result:   nil,
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := MatchBrandAlias(tt.result)
			if got != tt.expected {
				t.Errorf("MatchBrandAlias() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestResolveProvider(t *testing.T) {
	tests := []struct {
		name      string
		rdns      string
		apiResult *APIResult
		expected  string
	}{
		{
			name:      "tier 1 wins over tier 2",
			rdns:      "box.feral.io",
			apiResult: &APIResult{Datacenter: "Some Other DC"},
			expected:  "Feral",
		},
		{
			name:      "tier 2 brand alias when no rDNS match",
			rdns:      "generic.host.net",
			apiResult: &APIResult{ASN: 208959, Datacenter: "SlashN Services"},
			expected:  "Ultra.cc",
		},
		{
			name:      "tier 3 datacenter passthrough",
			rdns:      "generic.host.net",
			apiResult: &APIResult{ASN: 12345, Datacenter: "Hetzner"},
			expected:  "Hetzner",
		},
		{
			name:      "no match at any tier",
			rdns:      "home.comcast.net",
			apiResult: &APIResult{ASN: 7922},
			expected:  "",
		},
		{
			name:      "rDNS only, no API result",
			rdns:      "sb.whatbox.ca",
			apiResult: nil,
			expected:  "Whatbox",
		},
		{
			name:      "no rDNS, no API result",
			rdns:      "",
			apiResult: nil,
			expected:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ResolveProvider(tt.rdns, tt.apiResult)
			if got != tt.expected {
				t.Errorf("ResolveProvider(%q, ...) = %q, want %q", tt.rdns, got, tt.expected)
			}
		})
	}
}

func TestExtractDomain(t *testing.T) {
	tests := []struct {
		email    string
		expected string
	}{
		{"abuse@usbx.me", "usbx.me"},
		{"admin@feral.io", "feral.io"},
		{"noemail", ""},
		{"", ""},
		{"user@", ""},
	}

	for _, tt := range tests {
		t.Run(tt.email, func(t *testing.T) {
			got := extractEmailDomain(tt.email)
			if got != tt.expected {
				t.Errorf("extractEmailDomain(%q) = %q, want %q", tt.email, got, tt.expected)
			}
		})
	}
}
