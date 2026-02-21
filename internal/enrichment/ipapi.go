package enrichment

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// IPAPIClient implements NetworkLookup against the ipapi.is free API.
type IPAPIClient struct {
	httpClient *http.Client
	baseURL    string
}

// NewIPAPIClient creates an ipapi.is client.
func NewIPAPIClient(httpClient *http.Client) *IPAPIClient {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	return &IPAPIClient{
		httpClient: httpClient,
		baseURL:    "https://api.ipapi.is",
	}
}

// Lookup queries ipapi.is for full network metadata.
func (c *IPAPIClient) Lookup(ctx context.Context, ip string) (*APIResult, error) {
	url := fmt.Sprintf("%s/?q=%s", c.baseURL, ip)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("ipapi.is request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("ipapi.is returned %d: %s", resp.StatusCode, body)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	return parseIPAPIResponse(body)
}

// ipAPIResponse mirrors the ipapi.is JSON response structure (relevant fields only).
type ipAPIResponse struct {
	IsDatacenter bool `json:"is_datacenter"`
	Datacenter   *struct {
		Datacenter string `json:"datacenter"`
		Domain     string `json:"domain"`
	} `json:"datacenter"`
	Company *struct {
		Name   string `json:"name"`
		Domain string `json:"domain"`
		Type   string `json:"type"`
	} `json:"company"`
	Abuse *struct {
		Email string `json:"email"`
	} `json:"abuse"`
	ASN *struct {
		ASN   int    `json:"asn"`
		Route string `json:"route"`
		Org   string `json:"org"`
		Type  string `json:"type"`
	} `json:"asn"`
	Location *struct {
		City      string  `json:"city"`
		State     string  `json:"state"`
		Country   string  `json:"country_code"`
		Latitude  float64 `json:"latitude"`
		Longitude float64 `json:"longitude"`
	} `json:"location"`
}

func parseIPAPIResponse(data []byte) (*APIResult, error) {
	var raw ipAPIResponse
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parsing ipapi.is response: %w", err)
	}

	result := &APIResult{
		IsDatacenter: raw.IsDatacenter,
	}

	if raw.ASN != nil {
		result.ASN = raw.ASN.ASN
		result.ASNOrg = raw.ASN.Org
		result.BGPPrefix = raw.ASN.Route
	}
	if raw.Company != nil {
		result.ISP = raw.Company.Name
		result.CompanyType = raw.Company.Type
		result.CompanyDomain = raw.Company.Domain
	}
	if raw.Datacenter != nil {
		result.Datacenter = raw.Datacenter.Datacenter
		result.DCDomain = raw.Datacenter.Domain
	}
	if raw.Abuse != nil {
		result.AbuseEmail = raw.Abuse.Email
	}
	if raw.Location != nil {
		result.City = raw.Location.City
		result.Region = raw.Location.State
		result.Country = raw.Location.Country
		result.Latitude = raw.Location.Latitude
		result.Longitude = raw.Location.Longitude
	}

	return result, nil
}
