package aliesa

import (
	"net/http"
	"net/url"
	"testing"
)

func TestRPCSignatureMatchesAlibabaCloudExample(t *testing.T) {
	// Example from the Alibaba Cloud RPC signature documentation:
	// AccessKeyId=testid, AccessKeySecret=testsecret.
	params := url.Values{
		"Timestamp":        {"2016-02-23T12:46:24Z"},
		"Format":           {"XML"},
		"AccessKeyId":      {"testid"},
		"Action":           {"DescribeRegions"},
		"SignatureMethod":  {"HMAC-SHA1"},
		"SignatureNonce":   {"3ee8c1b8-83d3-44af-a94f-4e0ad82fd6cf"},
		"Version":          {"2014-05-26"},
		"SignatureVersion": {"1.0"},
	}

	const want = "OLeaidS1JvxuMvnyHOwuJ+uX5qY="
	if got := rpcSignature(http.MethodGet, params, "testsecret"); got != want {
		t.Fatalf("rpcSignature() = %q, want %q", got, want)
	}
}

func TestNormalizeEndpoint(t *testing.T) {
	tests := []struct {
		name     string
		endpoint string
		region   string
		want     string
	}{
		{name: "default", want: "https://esa.cn-hangzhou.aliyuncs.com"},
		{name: "region", region: "ap-southeast-1", want: "https://esa.ap-southeast-1.aliyuncs.com"},
		{name: "host only", endpoint: "esa.cn-hangzhou.aliyuncs.com", want: "https://esa.cn-hangzhou.aliyuncs.com"},
		{name: "http test server", endpoint: "http://127.0.0.1:8080/path", want: "http://127.0.0.1:8080"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := normalizeEndpoint(tc.endpoint, tc.region)
			if err != nil {
				t.Fatalf("normalizeEndpoint() error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("normalizeEndpoint() = %q, want %q", got, tc.want)
			}
		})
	}
}
