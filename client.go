package aliesa

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	requestTimeout = 30 * time.Second
	maxAttempts    = 3
)

// apiClient is a minimal client for the Alibaba Cloud ESA RPC API.
type apiClient struct {
	endpoint        string
	accessKeyID     string
	accessKeySecret string
	securityToken   string
	httpClient      *http.Client
	now             func() time.Time
	nonce           func() string
	userAgent       string
}

func newAPIClient(endpoint, accessKeyID, accessKeySecret, securityToken string) *apiClient {
	return &apiClient{
		endpoint:        strings.TrimRight(endpoint, "/"),
		accessKeyID:     accessKeyID,
		accessKeySecret: accessKeySecret,
		securityToken:   securityToken,
		httpClient:      &http.Client{Timeout: requestTimeout},
		now:             time.Now,
		nonce:           newNonce,
		userAgent:       "caddy-dns/aliesa",
	}
}

func newNonce() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return strconv.FormatInt(time.Now().UnixNano(), 10)
	}
	return hex.EncodeToString(b[:])
}

// do performs one signed RPC request. All parameters are sent in the query
// string, which is how the official ESA SDK calls these RPC actions.
func (c *apiClient) do(ctx context.Context, action, method string, params url.Values, out any) error {
	base := cloneValues(params)

	var lastErr error
	for attempt := 0; attempt < maxAttempts; attempt++ {
		requestParams := cloneValues(base)
		requestParams.Set("Action", action)
		requestParams.Set("Version", apiVersion)
		requestParams.Set("Format", "json")
		requestParams.Set("AccessKeyId", c.accessKeyID)
		requestParams.Set("SignatureMethod", "HMAC-SHA1")
		requestParams.Set("SignatureVersion", "1.0")
		requestParams.Set("SignatureNonce", c.nonce())
		requestParams.Set("Timestamp", c.now().UTC().Format("2006-01-02T15:04:05Z"))
		if c.securityToken != "" {
			requestParams.Set("SecurityToken", c.securityToken)
		}
		requestParams.Set("Signature", rpcSignature(method, requestParams, c.accessKeySecret))

		req, err := http.NewRequestWithContext(ctx, method, c.endpoint+"/?"+requestParams.Encode(), http.NoBody)
		if err != nil {
			return fmt.Errorf("aliesa: create request: %w", err)
		}
		req.Header.Set("Accept", "application/json")
		req.Header.Set("User-Agent", c.userAgent)
		req.Header.Set("x-acs-version", apiVersion)
		req.Header.Set("x-acs-action", action)

		resp, err := c.httpClient.Do(req)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			lastErr = fmt.Errorf("aliesa: %s request failed: %w", action, err)
			if attempt+1 < maxAttempts {
				if err := sleepContext(ctx, retryDelay(attempt)); err != nil {
					return err
				}
				continue
			}
			break
		}

		body, readErr := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
		resp.Body.Close()
		if readErr != nil {
			lastErr = fmt.Errorf("aliesa: read %s response: %w", action, readErr)
			if attempt+1 < maxAttempts {
				if err := sleepContext(ctx, retryDelay(attempt)); err != nil {
					return err
				}
				continue
			}
			break
		}

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			if out != nil && len(bytes.TrimSpace(body)) > 0 {
				if err := json.Unmarshal(body, out); err != nil {
					return fmt.Errorf("aliesa: decode %s response: %w", action, err)
				}
			}
			return nil
		}

		apiErr := parseAPIError(resp.StatusCode, body)
		lastErr = apiErr
		if apiErr.retryable() && attempt+1 < maxAttempts {
			if err := sleepContext(ctx, retryDelay(attempt)); err != nil {
				return err
			}
			continue
		}
		break
	}

	if lastErr == nil {
		lastErr = fmt.Errorf("aliesa: %s request failed", action)
	}
	return lastErr
}

func cloneValues(values url.Values) url.Values {
	out := make(url.Values, len(values))
	for key, vals := range values {
		out[key] = append([]string(nil), vals...)
	}
	return out
}

// rpcSignature implements the Alibaba Cloud RPC (HMAC-SHA1, version 1.0)
// signature algorithm.
func rpcSignature(method string, params url.Values, accessKeySecret string) string {
	canonical := params.Encode()
	canonical = strings.ReplaceAll(canonical, "+", "%20")
	canonical = strings.ReplaceAll(canonical, "*", "%2A")
	canonical = strings.ReplaceAll(canonical, "%7E", "~")

	stringToSign := method + "&%2F&" + url.QueryEscape(canonical)

	mac := hmac.New(sha1.New, []byte(accessKeySecret+"&"))
	_, _ = mac.Write([]byte(stringToSign))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

func retryDelay(attempt int) time.Duration {
	return time.Duration(250*(1<<attempt)) * time.Millisecond
}

func sleepContext(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

type apiError struct {
	StatusCode int
	Code       string
	Message    string
	RequestID  string
}

func (e *apiError) Error() string {
	if e.Code == "" {
		return fmt.Sprintf("ESA API request failed with HTTP %d: %s", e.StatusCode, e.Message)
	}
	message := fmt.Sprintf("ESA API error %s: %s (HTTP %d", e.Code, e.Message, e.StatusCode)
	if e.RequestID != "" {
		message += ", RequestId: " + e.RequestID
	}
	return message + ")"
}

func (e *apiError) retryable() bool {
	if e.StatusCode == http.StatusTooManyRequests || e.StatusCode >= 500 {
		return true
	}
	code := strings.ToLower(e.Code)
	if strings.HasPrefix(code, "throttling") {
		return true
	}
	switch code {
	case "internalerror", "internalexception", "serviceunavailable", "record.reserved", "record.servicebusy":
		return true
	default:
		return false
	}
}

func parseAPIError(statusCode int, body []byte) *apiError {
	var payload struct {
		Code      string `json:"Code"`
		Message   string `json:"Message"`
		RequestID string `json:"RequestId"`
	}
	_ = json.Unmarshal(body, &payload)

	if payload.Code == "" && payload.Message == "" {
		payload.Message = strings.TrimSpace(string(body))
		if len(payload.Message) > 512 {
			payload.Message = payload.Message[:512] + "..."
		}
	}

	return &apiError{
		StatusCode: statusCode,
		Code:       payload.Code,
		Message:    payload.Message,
		RequestID:  payload.RequestID,
	}
}

type siteInfo struct {
	SiteID     int64  `json:"SiteId"`
	SiteName   string `json:"SiteName"`
	AccessType string `json:"AccessType"`
}

type listSitesResponse struct {
	RequestID  string     `json:"RequestId"`
	PageNumber int        `json:"PageNumber"`
	PageSize   int        `json:"PageSize"`
	TotalCount int        `json:"TotalCount"`
	Sites      []siteInfo `json:"Sites"`
}

func (c *apiClient) listSitesPage(ctx context.Context, page, pageSize int, siteName, searchType string) (*listSitesResponse, error) {
	params := url.Values{}
	params.Set("PageNumber", strconv.Itoa(page))
	params.Set("PageSize", strconv.Itoa(pageSize))
	if siteName != "" {
		params.Set("SiteName", siteName)
		if searchType != "" {
			params.Set("SiteSearchType", searchType)
		}
	}

	var resp listSitesResponse
	if err := c.do(ctx, "ListSites", http.MethodGet, params, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

const listPageSize = 500

func (c *apiClient) listAllSites(ctx context.Context, siteName, searchType string) ([]siteInfo, error) {
	var all []siteInfo
	for page := 1; page <= 1000; page++ {
		resp, err := c.listSitesPage(ctx, page, listPageSize, siteName, searchType)
		if err != nil {
			return nil, err
		}
		all = append(all, resp.Sites...)
		if len(resp.Sites) == 0 {
			break
		}
		if resp.TotalCount > 0 && len(all) >= resp.TotalCount {
			break
		}
		if len(resp.Sites) < listPageSize {
			break
		}
	}
	return all, nil
}

type apiRecordData struct {
	Value        string `json:"Value"`
	Priority     int32  `json:"Priority"`
	Flag         int32  `json:"Flag"`
	Tag          string `json:"Tag"`
	Weight       int32  `json:"Weight"`
	Port         int32  `json:"Port"`
	Type         int32  `json:"Type"`
	KeyTag       int32  `json:"KeyTag"`
	Algorithm    int32  `json:"Algorithm"`
	Certificate  string `json:"Certificate"`
	Usage        int32  `json:"Usage"`
	Selector     int32  `json:"Selector"`
	MatchingType int32  `json:"MatchingType"`
	Fingerprint  string `json:"Fingerprint"`
}

type apiRecord struct {
	RecordID         int64         `json:"RecordId"`
	RecordName       string        `json:"RecordName"`
	RecordType       string        `json:"RecordType"`
	Data             apiRecordData `json:"Data"`
	TTL              int64         `json:"Ttl"`
	Proxied          bool          `json:"Proxied"`
	RecordSourceType string        `json:"RecordSourceType"`
	SiteID           int64         `json:"SiteId"`
	SiteName         string        `json:"SiteName"`
}

type listRecordsResponse struct {
	RequestID  string      `json:"RequestId"`
	PageNumber int         `json:"PageNumber"`
	PageSize   int         `json:"PageSize"`
	TotalCount int         `json:"TotalCount"`
	Records    []apiRecord `json:"Records"`
}

func (c *apiClient) listRecordsPage(ctx context.Context, siteID int64, page, pageSize int, recordName string) (*listRecordsResponse, error) {
	params := url.Values{}
	params.Set("SiteId", strconv.FormatInt(siteID, 10))
	params.Set("PageNumber", strconv.Itoa(page))
	params.Set("PageSize", strconv.Itoa(pageSize))
	if recordName != "" {
		params.Set("RecordName", recordName)
		params.Set("RecordMatchType", "exact")
	}

	var resp listRecordsResponse
	if err := c.do(ctx, "ListRecords", http.MethodGet, params, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *apiClient) listAllRecords(ctx context.Context, siteID int64) ([]apiRecord, error) {
	return c.listAllRecordsByName(ctx, siteID, "")
}

func (c *apiClient) listAllRecordsByName(ctx context.Context, siteID int64, recordName string) ([]apiRecord, error) {
	var all []apiRecord
	for page := 1; page <= 1000; page++ {
		resp, err := c.listRecordsPage(ctx, siteID, page, listPageSize, recordName)
		if err != nil {
			return nil, err
		}
		all = append(all, resp.Records...)
		if len(resp.Records) == 0 {
			break
		}
		if resp.TotalCount > 0 && len(all) >= resp.TotalCount {
			break
		}
		if len(resp.Records) < listPageSize {
			break
		}
	}
	return all, nil
}

type apiRecordDataInput struct {
	Value        string `json:"Value,omitempty"`
	Priority     *int32 `json:"Priority,omitempty"`
	Flag         *int32 `json:"Flag,omitempty"`
	Tag          string `json:"Tag,omitempty"`
	Weight       *int32 `json:"Weight,omitempty"`
	Port         *int32 `json:"Port,omitempty"`
	Type         *int32 `json:"Type,omitempty"`
	KeyTag       *int32 `json:"KeyTag,omitempty"`
	Algorithm    *int32 `json:"Algorithm,omitempty"`
	Certificate  string `json:"Certificate,omitempty"`
	Usage        *int32 `json:"Usage,omitempty"`
	Selector     *int32 `json:"Selector,omitempty"`
	MatchingType *int32 `json:"MatchingType,omitempty"`
	Fingerprint  string `json:"Fingerprint,omitempty"`
}

type recordInput struct {
	SiteID     int64
	Name       string
	Type       string
	TTL        int64
	Data       apiRecordDataInput
	Proxied    *bool
	SourceType string
	BizName    string
}

func (c *apiClient) createRecord(ctx context.Context, in recordInput) (int64, error) {
	dataJSON, err := json.Marshal(in.Data)
	if err != nil {
		return 0, fmt.Errorf("aliesa: encode record data: %w", err)
	}

	params := url.Values{}
	params.Set("SiteId", strconv.FormatInt(in.SiteID, 10))
	params.Set("RecordName", in.Name)
	params.Set("Type", in.Type)
	params.Set("Ttl", strconv.FormatInt(in.TTL, 10))
	params.Set("Data", string(dataJSON))
	if in.Proxied != nil {
		params.Set("Proxied", strconv.FormatBool(*in.Proxied))
	}
	if in.SourceType != "" {
		params.Set("SourceType", in.SourceType)
	}
	if in.BizName != "" {
		params.Set("BizName", in.BizName)
	}

	var resp struct {
		RequestID string `json:"RequestId"`
		RecordID  int64  `json:"RecordId"`
	}
	if err := c.do(ctx, "CreateRecord", http.MethodPost, params, &resp); err != nil {
		return 0, err
	}
	return resp.RecordID, nil
}

func (c *apiClient) updateRecord(ctx context.Context, recordID int64, in recordInput) error {
	dataJSON, err := json.Marshal(in.Data)
	if err != nil {
		return fmt.Errorf("aliesa: encode record data: %w", err)
	}

	params := url.Values{}
	params.Set("RecordId", strconv.FormatInt(recordID, 10))
	params.Set("Type", in.Type)
	params.Set("Ttl", strconv.FormatInt(in.TTL, 10))
	params.Set("Data", string(dataJSON))
	if in.Proxied != nil {
		params.Set("Proxied", strconv.FormatBool(*in.Proxied))
	}
	if in.SourceType != "" {
		params.Set("SourceType", in.SourceType)
	}
	if in.BizName != "" {
		params.Set("BizName", in.BizName)
	}

	return c.do(ctx, "UpdateRecord", http.MethodPost, params, nil)
}

func (c *apiClient) deleteRecord(ctx context.Context, recordID int64) error {
	params := url.Values{}
	params.Set("RecordId", strconv.FormatInt(recordID, 10))
	err := c.do(ctx, "DeleteRecord", http.MethodPost, params, nil)
	if err == nil {
		return nil
	}
	var apiErr *apiError
	if errors.As(err, &apiErr) && apiErr.Code == "Record.NotFound" {
		return nil
	}
	return err
}

func boolPtr(v bool) *bool { return &v }

func int32Ptr(v int32) *int32 { return &v }
