package enrichment

import "strings"

// rDNS patterns for tier 1 provider identification.
// Each entry maps a hostname substring or suffix to a provider name.
var rdnsPatterns = []struct {
	pattern  string
	suffix   bool // true = match as suffix, false = match as substring
	provider string
}{
	{".feral.io", true, "Feral"},
	{"feralhosting", false, "Feral"},
	{"whatbox", false, "Whatbox"},
	{"bytesized", false, "Bytesized"},
	{"seedboxes.cc", false, "Seedboxes.cc"},
	{"ultraseedbox", false, "Ultra.cc"},
	{".ultra.cc", true, "Ultra.cc"},
	{"rapidseedbox", false, "RapidSeedbox"},
	{"seedhost", false, "Seedhost.eu"},
	{"pulsedmedia", false, "PulsedMedia"},
	{"hostingbydesign", false, "HostingByDesign"},
	{"sbdx", false, "HostingByDesign"},
	{"leaseweb", false, "Leaseweb"},
	{"hostdzire", false, "Leaseweb"},
	{"hetzner", false, "Hetzner"},
	{"netcup", false, "netcup"},
	{"hosthatch", false, "HostHatch"},
	{"scaleway", false, "Scaleway"},
	{"ovh.", false, "OVH"},
	{".ovh", true, "OVH"},
}

// Brand alias maps: ASN and domain → consumer brand name.
// ipapi.is returns corporate entity names; these map to well-known brands.
var (
	asnBrands = map[int]string{
		208959: "Ultra.cc", // SlashN Services
		200052: "Feral",    // Feral Hosting
	}

	domainBrands = map[string]string{
		"slashn.com":            "Ultra.cc",
		"usbx.me":               "Ultra.cc",
		"ultra.cc":              "Ultra.cc",
		"feral.io":              "Feral",
		"feralhosting.com":      "Feral",
		"whatbox.ca":            "Whatbox",
		"bytesized-hosting.com": "Bytesized",
		"seedhost.eu":           "Seedhost.eu",
		"pulsedmedia.com":       "PulsedMedia",
		"rapidseedbox.com":      "RapidSeedbox",
		"seedboxes.cc":          "Seedboxes.cc",
		"hostingbydesign.com":   "HostingByDesign",
		"leaseweb.com":          "Leaseweb",
		"leaseweb.nl":           "Leaseweb",
		"hetzner.com":           "Hetzner",
		"hetzner.de":            "Hetzner",
		"netcup.de":             "netcup",
		"hosthatch.com":         "HostHatch",
		"scaleway.com":          "Scaleway",
		"ovh.net":               "OVH",
		"ovhcloud.com":          "OVH",
	}
)

// MatchRDNS attempts tier-1 provider identification from a reverse DNS hostname.
// Returns the provider name, or empty string if no match.
func MatchRDNS(rdns string) string {
	if rdns == "" {
		return ""
	}
	lower := strings.ToLower(rdns)
	for _, p := range rdnsPatterns {
		if p.suffix {
			if strings.HasSuffix(lower, p.pattern) {
				return p.provider
			}
		} else {
			if strings.Contains(lower, p.pattern) {
				return p.provider
			}
		}
	}
	return ""
}

// MatchBrandAlias attempts tier-2 provider identification from ipapi.is fields.
// Checks ASN, company domain, datacenter domain, and abuse email domain
// against the brand alias maps. Returns the provider name, or empty string.
func MatchBrandAlias(result *APIResult) string {
	if result == nil {
		return ""
	}

	// Check ASN
	if brand, ok := asnBrands[result.ASN]; ok {
		return brand
	}

	// Check domains in priority order
	for _, domain := range []string{
		result.CompanyDomain,
		result.DCDomain,
		extractEmailDomain(result.AbuseEmail),
	} {
		if domain == "" {
			continue
		}
		if brand, ok := domainBrands[strings.ToLower(domain)]; ok {
			return brand
		}
	}

	return ""
}

// ResolveProvider runs the three-tier provider identification.
// Tier 1: rDNS pattern match (highest confidence).
// Tier 2: brand alias map on ipapi.is fields.
// Tier 3: raw datacenter name passthrough from ipapi.is.
func ResolveProvider(rdns string, apiResult *APIResult) string {
	// Tier 1: rDNS
	if provider := MatchRDNS(rdns); provider != "" {
		return provider
	}

	// Tier 2: brand alias
	if provider := MatchBrandAlias(apiResult); provider != "" {
		return provider
	}

	// Tier 3: datacenter passthrough
	if apiResult != nil && apiResult.Datacenter != "" {
		return apiResult.Datacenter
	}

	return ""
}

// extractEmailDomain extracts the domain part from an email address.
func extractEmailDomain(email string) string {
	parts := strings.SplitN(email, "@", 2)
	if len(parts) != 2 || parts[1] == "" {
		return ""
	}
	return parts[1]
}
