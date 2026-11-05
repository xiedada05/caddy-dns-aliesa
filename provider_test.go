package aliesa

import (
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

func TestCaddyModuleRegistered(t *testing.T) {
	info, err := caddy.GetModule(moduleID)
	if err != nil {
		t.Fatalf("GetModule(%q) error: %v", moduleID, err)
	}
	if _, ok := info.New().(*Provider); !ok {
		t.Fatalf("module %q returned %T, want *Provider", moduleID, info.New())
	}
}

func TestUnmarshalCaddyfile(t *testing.T) {
	var provider Provider
	input := `aliesa {
		access_key_id test-id
		access_key_secret test-secret
		security_token test-token
		region_id ap-southeast-1
		endpoint https://example.invalid
		ttl 120
		proxied true
		biz_name api
	}`
	if err := provider.UnmarshalCaddyfile(caddyfile.NewTestDispenser(input)); err != nil {
		t.Fatalf("UnmarshalCaddyfile() error: %v", err)
	}

	if provider.AccessKeyID != "test-id" ||
		provider.AccessKeySecret != "test-secret" ||
		provider.SecurityToken != "test-token" ||
		provider.RegionID != "ap-southeast-1" ||
		provider.Endpoint != "https://example.invalid" ||
		provider.TTL != 120 ||
		provider.Proxied == nil || !*provider.Proxied ||
		provider.BizName != "api" {
		t.Fatalf("unexpected provider config: %#v", provider)
	}
}

func TestProvisionDefaultsAndEnvironment(t *testing.T) {
	t.Setenv("ALIESA_ACCESS_KEY_ID", "env-id")
	t.Setenv("ALIESA_ACCESS_KEY_SECRET", "env-secret")

	var provider Provider
	input := `aliesa {
		region_id ap-southeast-1
	}`
	if err := provider.UnmarshalCaddyfile(caddyfile.NewTestDispenser(input)); err != nil {
		t.Fatalf("UnmarshalCaddyfile() error: %v", err)
	}
	if err := provider.Provision(caddy.Context{}); err != nil {
		t.Fatalf("Provision() error: %v", err)
	}

	if provider.AccessKeyID != "env-id" || provider.AccessKeySecret != "env-secret" {
		t.Fatalf("environment credentials were not used: %#v", provider)
	}
	if provider.TTL != defaultTTL {
		t.Fatalf("TTL = %d, want %d", provider.TTL, defaultTTL)
	}
	if provider.BizName != "web" {
		t.Fatalf("BizName = %q, want web", provider.BizName)
	}
	if provider.client == nil || provider.client.endpoint != "https://esa.ap-southeast-1.aliyuncs.com" {
		t.Fatalf("unexpected client: %#v", provider.client)
	}
	if provider.state == nil {
		t.Fatal("provider state was not initialized")
	}
}

func TestProvisionRejectsMissingCredentials(t *testing.T) {
	t.Setenv("ALIESA_ACCESS_KEY_ID", "")
	t.Setenv("ALIESA_ACCESS_KEY_SECRET", "")
	t.Setenv("ALIBABA_CLOUD_ACCESS_KEY_ID", "")
	t.Setenv("ALIBABA_CLOUD_ACCESS_KEY_SECRET", "")

	var provider Provider
	if err := provider.Provision(caddy.Context{}); err == nil {
		t.Fatal("Provision() succeeded without credentials, want error")
	}
}

func TestProvisionRejectsInvalidTTL(t *testing.T) {
	provider := Provider{
		AccessKeyID:     "id",
		AccessKeySecret: "secret",
		TTL:             5,
	}
	if err := provider.Provision(caddy.Context{}); err == nil {
		t.Fatal("Provision() succeeded with invalid TTL, want error")
	}
}
