package enrichment

import "testing"

func TestReverseIP(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"1.2.3.4", "4.3.2.1"},
		{"8.8.8.8", "8.8.8.8"},
		{"192.168.1.100", "100.1.168.192"},
		{"invalid", "invalid"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := reverseIP(tt.input)
			if got != tt.expected {
				t.Errorf("reverseIP(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

func TestParseCymruOrigin(t *testing.T) {
	tests := []struct {
		name    string
		txt     string
		wantASN int
		wantPfx string
		wantCC  string
	}{
		{
			name:    "standard response",
			txt:     "15169 | 8.8.8.0/24 | US | arin | 2014-03-14",
			wantASN: 15169, wantPfx: "8.8.8.0/24", wantCC: "US",
		},
		{
			name:    "different ASN",
			txt:     "208959 | 216.163.184.0/24 | NL | ripe | 2019-05-06",
			wantASN: 208959, wantPfx: "216.163.184.0/24", wantCC: "NL",
		},
		{
			name:    "too few fields",
			txt:     "15169 | 8.8.8.0/24",
			wantASN: 0, wantPfx: "", wantCC: "",
		},
		{
			name:    "empty string",
			txt:     "",
			wantASN: 0, wantPfx: "", wantCC: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := &DNSResult{}
			parseCymruOrigin(tt.txt, result)
			if result.ASN != tt.wantASN {
				t.Errorf("ASN = %d, want %d", result.ASN, tt.wantASN)
			}
			if result.BGPPrefix != tt.wantPfx {
				t.Errorf("BGPPrefix = %q, want %q", result.BGPPrefix, tt.wantPfx)
			}
			if result.Country != tt.wantCC {
				t.Errorf("Country = %q, want %q", result.Country, tt.wantCC)
			}
		})
	}
}
