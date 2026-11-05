// Package aliesa implements a Caddy DNS provider for Alibaba Cloud Edge
// Security Acceleration (ESA).
package aliesa

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/libdns/libdns"
)

const (
	moduleID = "dns.providers.aliesa"

	// ESA OpenAPI version.
	apiVersion = "2024-09-10"

	defaultRegionID = "cn-hangzhou"
	defaultTTL      = 600
	minTTL          = 30
	maxTTL          = 86400
)

var validBizNames = map[string]struct{}{
	"web":         {},
	"api":         {},
	"image_video": {},
	"file":        {},
	"ai":          {},
}

// Provider is the Caddy module that manages DNS records in Alibaba Cloud ESA.
type Provider struct {
	// AccessKeyID is the Alibaba Cloud AccessKey ID.
	AccessKeyID string `json:"access_key_id,omitempty"`

	// AccessKeySecret is the Alibaba Cloud AccessKey secret.
	AccessKeySecret string `json:"access_key_secret,omitempty"`

	// SecurityToken is an optional STS token. It is required when the
	// credentials come from AssumeRole.
	SecurityToken string `json:"security_token,omitempty"`

	// RegionID selects the ESA API endpoint. Defaults to cn-hangzhou.
	// Common values are cn-hangzhou and ap-southeast-1.
	RegionID string `json:"region_id,omitempty"`

	// Endpoint overrides the ESA API endpoint. It is useful for testing or
	// for private gateways. The default is https://esa.<region_id>.aliyuncs.com.
	Endpoint string `json:"endpoint,omitempty"`

	// TTL is used when a libdns record does not specify a TTL. ESA accepts
	// 30-86400 seconds, or 1 for "automatic". The default is 600.
	TTL int `json:"ttl,omitempty"`

	// Proxied controls proxy acceleration for newly created A/AAAA and CNAME
	// records. When unset, it follows the site access type: CNAME sites get
	// proxy acceleration, NS sites do not.
	Proxied *bool `json:"proxied,omitempty"`

	// BizName is the business scenario used when proxy acceleration is enabled.
	// Valid values are web, api, image_video, file, and ai. Defaults to web.
	BizName string `json:"biz_name,omitempty"`

	client *apiClient
	state  *providerState
}

type providerState struct {
	mu        sync.Mutex
	siteCache map[string]siteInfo
	writeMu   sync.Mutex
}

func init() {
	caddy.RegisterModule(Provider{})
}

// CaddyModule returns the Caddy module information.
func (Provider) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  moduleID,
		New: func() caddy.Module { return new(Provider) },
	}
}

// Provision prepares the provider from the Caddy configuration.
func (p *Provider) Provision(_ caddy.Context) error {
	repl := caddy.NewReplacer()
	p.AccessKeyID = strings.TrimSpace(repl.ReplaceAll(p.AccessKeyID, ""))
	p.AccessKeySecret = strings.TrimSpace(repl.ReplaceAll(p.AccessKeySecret, ""))
	p.SecurityToken = strings.TrimSpace(repl.ReplaceAll(p.SecurityToken, ""))
	p.RegionID = strings.TrimSpace(repl.ReplaceAll(p.RegionID, ""))
	p.Endpoint = strings.TrimSpace(repl.ReplaceAll(p.Endpoint, ""))
	p.BizName = strings.TrimSpace(repl.ReplaceAll(p.BizName, ""))

	if p.AccessKeyID == "" {
		p.AccessKeyID = firstEnv("ALIESA_ACCESS_KEY_ID", "ALIBABA_CLOUD_ACCESS_KEY_ID")
	}
	if p.AccessKeySecret == "" {
		p.AccessKeySecret = firstEnv("ALIESA_ACCESS_KEY_SECRET", "ALIBABA_CLOUD_ACCESS_KEY_SECRET")
	}
	if p.SecurityToken == "" {
		p.SecurityToken = firstEnv("ALIESA_SECURITY_TOKEN", "ALIBABA_CLOUD_SECURITY_TOKEN")
	}

	if p.AccessKeyID == "" {
		return errors.New("aliesa: access_key_id is required")
	}
	if p.AccessKeySecret == "" {
		return errors.New("aliesa: access_key_secret is required")
	}

	if p.RegionID == "" {
		p.RegionID = defaultRegionID
	}

	if p.TTL == 0 {
		p.TTL = defaultTTL
	}
	if p.TTL != 1 && (p.TTL < minTTL || p.TTL > maxTTL) {
		return fmt.Errorf("aliesa: ttl must be 1 or between %d and %d seconds", minTTL, maxTTL)
	}

	if p.BizName == "" {
		p.BizName = "web"
	}
	if _, ok := validBizNames[p.BizName]; !ok {
		return fmt.Errorf("aliesa: biz_name %q is not valid (want web, api, image_video, file, or ai)", p.BizName)
	}

	endpoint, err := normalizeEndpoint(p.Endpoint, p.RegionID)
	if err != nil {
		return fmt.Errorf("aliesa: invalid endpoint: %w", err)
	}

	p.client = newAPIClient(endpoint, p.AccessKeyID, p.AccessKeySecret, p.SecurityToken)
	p.state = &providerState{siteCache: make(map[string]siteInfo)}

	return nil
}

// UnmarshalCaddyfile parses the Caddyfile configuration:
//
//	aliesa {
//		access_key_id <id>
//		access_key_secret <secret>
//		security_token <token>
//		region_id <region>
//		endpoint <url>
//		ttl <seconds>
//		proxied <true|false>
//		biz_name <web|api|image_video|file|ai>
//	}
func (p *Provider) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next() // consume the provider name

	if d.NextArg() {
		return d.ArgErr()
	}

	for nesting := d.Nesting(); d.NextBlock(nesting); {
		switch d.Val() {
		case "access_key_id":
			if !d.NextArg() {
				return d.ArgErr()
			}
			p.AccessKeyID = d.Val()

		case "access_key_secret":
			if !d.NextArg() {
				return d.ArgErr()
			}
			p.AccessKeySecret = d.Val()

		case "security_token":
			if !d.NextArg() {
				return d.ArgErr()
			}
			p.SecurityToken = d.Val()

		case "region_id":
			if !d.NextArg() {
				return d.ArgErr()
			}
			p.RegionID = d.Val()

		case "endpoint":
			if !d.NextArg() {
				return d.ArgErr()
			}
			p.Endpoint = d.Val()

		case "ttl":
			if !d.NextArg() {
				return d.ArgErr()
			}
			ttl, err := strconv.Atoi(d.Val())
			if err != nil {
				return d.Errf("invalid ttl %q: %v", d.Val(), err)
			}
			p.TTL = ttl

		case "proxied":
			proxied := true
			if d.NextArg() {
				value, err := strconv.ParseBool(d.Val())
				if err != nil {
					return d.Errf("invalid proxied value %q: %v", d.Val(), err)
				}
				proxied = value
			}
			p.Proxied = &proxied

		case "biz_name":
			if !d.NextArg() {
				return d.ArgErr()
			}
			p.BizName = d.Val()

		default:
			return d.Errf("unrecognized subdirective %q", d.Val())
		}

		if d.NextArg() {
			return d.ArgErr()
		}
	}

	return nil
}

func firstEnv(names ...string) string {
	for _, name := range names {
		if value := strings.TrimSpace(os.Getenv(name)); value != "" {
			return value
		}
	}
	return ""
}

func normalizeEndpoint(endpoint, regionID string) (string, error) {
	if endpoint == "" {
		if regionID == "" {
			regionID = defaultRegionID
		}
		endpoint = "https://esa." + regionID + ".aliyuncs.com"
	}
	if !strings.Contains(endpoint, "://") {
		endpoint = "https://" + endpoint
	}
	u, err := url.Parse(endpoint)
	if err != nil {
		return "", err
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", fmt.Errorf("unsupported scheme %q", u.Scheme)
	}
	if u.Host == "" {
		return "", errors.New("missing host")
	}
	return u.Scheme + "://" + u.Host, nil
}

// Interface guards.
var (
	_ caddy.Module          = (*Provider)(nil)
	_ caddy.Provisioner     = (*Provider)(nil)
	_ caddyfile.Unmarshaler = (*Provider)(nil)

	_ libdns.RecordGetter   = (*Provider)(nil)
	_ libdns.RecordAppender = (*Provider)(nil)
	_ libdns.RecordSetter   = (*Provider)(nil)
	_ libdns.RecordDeleter  = (*Provider)(nil)
	_ libdns.ZoneLister     = (*Provider)(nil)
)
