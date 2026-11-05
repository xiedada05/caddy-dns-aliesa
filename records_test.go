package aliesa

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/libdns/libdns"
)

type recordedRequest struct {
	Action string
	Method string
	Params url.Values
}

type fakeESA struct {
	t *testing.T

	mu       sync.Mutex
	requests []recordedRequest
	sites    []siteInfo
	records  []apiRecord
	nextID   int64

	failCreateCode string
}

func (f *fakeESA) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	params := r.URL.Query()
	action := params.Get("Action")

	f.mu.Lock()
	f.requests = append(f.requests, recordedRequest{Action: action, Method: r.Method, Params: params})
	f.mu.Unlock()

	switch action {
	case "ListSites":
		f.handleListSites(w, params)
	case "ListRecords":
		f.handleListRecords(w, params)
	case "CreateRecord":
		f.handleCreateRecord(w, params)
	case "UpdateRecord":
		writeJSON(w, http.StatusOK, map[string]any{"RequestId": "test", "RecordId": 0})
	case "DeleteRecord":
		writeJSON(w, http.StatusOK, map[string]any{"RequestId": "test"})
	default:
		writeAPIError(w, http.StatusBadRequest, "InvalidAction", "unknown action "+action)
	}
}

func (f *fakeESA) handleListSites(w http.ResponseWriter, params url.Values) {
	f.mu.Lock()
	sites := append([]siteInfo(nil), f.sites...)
	f.mu.Unlock()

	name := params.Get("SiteName")
	searchType := params.Get("SiteSearchType")
	if name != "" && searchType == "exact" {
		filtered := sites[:0]
		for _, site := range sites {
			if strings.EqualFold(site.SiteName, name) {
				filtered = append(filtered, site)
			}
		}
		sites = filtered
	}

	page := parseIntDefault(params.Get("PageNumber"), 1)
	size := parseIntDefault(params.Get("PageSize"), 500)
	start, end := pageBounds(page, size, len(sites))
	writeJSON(w, http.StatusOK, listSitesResponse{
		RequestID:  "test",
		PageNumber: page,
		PageSize:   size,
		TotalCount: len(sites),
		Sites:      sites[start:end],
	})
}

func (f *fakeESA) handleListRecords(w http.ResponseWriter, params url.Values) {
	f.mu.Lock()
	records := append([]apiRecord(nil), f.records...)
	f.mu.Unlock()

	page := parseIntDefault(params.Get("PageNumber"), 1)
	size := parseIntDefault(params.Get("PageSize"), 500)
	start, end := pageBounds(page, size, len(records))
	writeJSON(w, http.StatusOK, listRecordsResponse{
		RequestID:  "test",
		PageNumber: page,
		PageSize:   size,
		TotalCount: len(records),
		Records:    records[start:end],
	})
}

func (f *fakeESA) handleCreateRecord(w http.ResponseWriter, params url.Values) {
	f.mu.Lock()
	failCode := f.failCreateCode
	if failCode != "" {
		f.mu.Unlock()
		writeAPIError(w, http.StatusBadRequest, failCode, "duplicate record")
		return
	}
	f.nextID++
	id := f.nextID
	f.mu.Unlock()

	writeJSON(w, http.StatusOK, map[string]any{"RequestId": "test", "RecordId": id})
}

func (f *fakeESA) requestsFor(action string) []recordedRequest {
	f.mu.Lock()
	defer f.mu.Unlock()

	var out []recordedRequest
	for _, request := range f.requests {
		if request.Action == action {
			out = append(out, request)
		}
	}
	return out
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeAPIError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, map[string]any{
		"RequestId": "test",
		"Code":      code,
		"Message":   message,
	})
}

func parseIntDefault(value string, fallback int) int {
	if value == "" {
		return fallback
	}
	n, err := strconv.Atoi(value)
	if err != nil {
		return fallback
	}
	return n
}

func pageBounds(page, size, total int) (int, int) {
	if size <= 0 {
		size = 500
	}
	start := (page - 1) * size
	if start < 0 {
		start = 0
	}
	if start > total {
		start = total
	}
	end := start + size
	if end > total {
		end = total
	}
	return start, end
}

func newTestProvider(serverURL string, cache map[string]siteInfo) *Provider {
	return &Provider{
		TTL:     defaultTTL,
		BizName: "web",
		client:  newAPIClient(serverURL, "testid", "testsecret", ""),
		state:   &providerState{siteCache: cache},
	}
}

func defaultTestSite() siteInfo {
	return siteInfo{SiteID: 42, SiteName: "example.com", AccessType: "NS"}
}

func TestGetRecords(t *testing.T) {
	fake := &fakeESA{
		t: t,
		records: []apiRecord{
			{RecordID: 1, RecordName: "www.example.com", RecordType: "A/AAAA", TTL: 600, Data: apiRecordData{Value: "192.0.2.1,2001:db8::1"}},
			{RecordID: 2, RecordName: "_acme-challenge.example.com", RecordType: "TXT", TTL: 60, Data: apiRecordData{Value: "token"}},
			{RecordID: 3, RecordName: "example.com", RecordType: "MX", TTL: 3600, Data: apiRecordData{Value: "mail.example.com", Priority: 10}},
			{RecordID: 4, RecordName: "example.com", RecordType: "CAA", TTL: 3600, Data: apiRecordData{Value: "letsencrypt.org", Flag: 0, Tag: "issue"}},
			{RecordID: 5, RecordName: "_sip._tcp.example.com", RecordType: "SRV", TTL: 600, Data: apiRecordData{Value: "sip.example.com", Priority: 10, Weight: 5, Port: 5060}},
			{RecordID: 6, RecordName: "alias.example.com", RecordType: "CNAME", TTL: 300, Data: apiRecordData{Value: "target.example.net"}},
		},
	}
	server := httptest.NewServer(fake)
	defer server.Close()

	provider := newTestProvider(server.URL, map[string]siteInfo{"example.com": defaultTestSite()})
	records, err := provider.GetRecords(context.Background(), "example.com.")
	if err != nil {
		t.Fatalf("GetRecords() error: %v", err)
	}
	if len(records) != 7 {
		t.Fatalf("GetRecords() returned %d records, want 7: %#v", len(records), records)
	}

	var addresses []libdns.Address
	var txts []libdns.TXT
	var mx *libdns.MX
	var caa *libdns.CAA
	var srv *libdns.SRV
	var cname *libdns.CNAME
	for _, rec := range records {
		switch value := rec.(type) {
		case libdns.Address:
			addresses = append(addresses, value)
		case libdns.TXT:
			txts = append(txts, value)
		case libdns.MX:
			mx = &value
		case libdns.CAA:
			caa = &value
		case libdns.SRV:
			srv = &value
		case libdns.CNAME:
			cname = &value
		}
	}

	if len(addresses) != 2 {
		t.Fatalf("got %d address records, want 2", len(addresses))
	}
	if addresses[0].Name != "www" || addresses[0].TTL != 600*1e9 {
		t.Fatalf("unexpected first address: %#v", addresses[0])
	}
	if len(txts) != 1 || txts[0].Name != "_acme-challenge" || txts[0].Text != "token" || txts[0].TTL != 60*1e9 {
		t.Fatalf("unexpected TXT records: %#v", txts)
	}
	if mx == nil || mx.Name != "@" || mx.Preference != 10 || mx.Target != "mail.example.com." {
		t.Fatalf("unexpected MX record: %#v", mx)
	}
	if caa == nil || caa.Name != "@" || caa.Flags != 0 || caa.Tag != "issue" || caa.Value != "letsencrypt.org" {
		t.Fatalf("unexpected CAA record: %#v", caa)
	}
	if srv == nil || srv.Service != "sip" || srv.Transport != "tcp" || srv.Name != "@" || srv.Port != 5060 {
		t.Fatalf("unexpected SRV record: %#v", srv)
	}
	if cname == nil || cname.Name != "alias" || cname.Target != "target.example.net." {
		t.Fatalf("unexpected CNAME record: %#v", cname)
	}
}

func TestSiteSuffixFallback(t *testing.T) {
	fake := &fakeESA{
		t:     t,
		sites: []siteInfo{{SiteID: 7, SiteName: "example.com", AccessType: "NS"}},
		records: []apiRecord{
			{RecordID: 1, RecordName: "www.example.com", RecordType: "TXT", TTL: 60, Data: apiRecordData{Value: "hello"}},
		},
	}
	server := httptest.NewServer(fake)
	defer server.Close()

	provider := newTestProvider(server.URL, nil)
	records, err := provider.GetRecords(context.Background(), "www.example.com.")
	if err != nil {
		t.Fatalf("GetRecords() error: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("GetRecords() returned %d records, want 1", len(records))
	}
	if txt, ok := records[0].(libdns.TXT); !ok || txt.Name != "@" {
		t.Fatalf("unexpected record: %#v", records[0])
	}

	requests := fake.requestsFor("ListSites")
	if len(requests) != 2 {
		t.Fatalf("ListSites called %d times, want 2 (exact then suffix search)", len(requests))
	}
	recordsRequest := fake.requestsFor("ListRecords")
	if len(recordsRequest) != 1 || recordsRequest[0].Params.Get("SiteId") != "7" {
		t.Fatalf("unexpected ListRecords calls: %#v", recordsRequest)
	}
}

func TestAppendRecords(t *testing.T) {
	fake := &fakeESA{t: t}
	server := httptest.NewServer(fake)
	defer server.Close()

	provider := newTestProvider(server.URL, map[string]siteInfo{"example.com": defaultTestSite()})
	recs := []libdns.Record{
		libdns.RR{Type: "TXT", Name: "_acme-challenge", Data: "token"},
		libdns.Address{Name: "www", IP: netip.MustParseAddr("192.0.2.1")},
	}
	created, err := provider.AppendRecords(context.Background(), "example.com.", recs)
	if err != nil {
		t.Fatalf("AppendRecords() error: %v", err)
	}
	if len(created) != len(recs) {
		t.Fatalf("AppendRecords() returned %d records, want %d", len(created), len(recs))
	}

	requests := fake.requestsFor("CreateRecord")
	if len(requests) != 2 {
		t.Fatalf("CreateRecord called %d times, want 2", len(requests))
	}

	txt := requests[0].Params
	if txt.Get("RecordName") != "_acme-challenge.example.com" ||
		txt.Get("Type") != "TXT" ||
		txt.Get("Ttl") != "600" ||
		txt.Get("Data") != `{"Value":"token"}` {
		t.Fatalf("unexpected TXT create params: %v", txt)
	}
	if txt.Get("Proxied") != "" {
		t.Fatalf("TXT record must not set Proxied: %v", txt)
	}

	address := requests[1].Params
	if address.Get("RecordName") != "www.example.com" ||
		address.Get("Type") != "A/AAAA" ||
		address.Get("Data") != `{"Value":"192.0.2.1"}` ||
		address.Get("Proxied") != "false" {
		t.Fatalf("unexpected address create params: %v", address)
	}
}

func TestAppendCNAMEOnCNAMESiteUsesProxy(t *testing.T) {
	fake := &fakeESA{t: t}
	server := httptest.NewServer(fake)
	defer server.Close()

	site := siteInfo{SiteID: 42, SiteName: "example.com", AccessType: "CNAME"}
	provider := newTestProvider(server.URL, map[string]siteInfo{"example.com": site})

	_, err := provider.AppendRecords(context.Background(), "example.com.", []libdns.Record{
		libdns.CNAME{Name: "www", Target: "target.example.net."},
	})
	if err != nil {
		t.Fatalf("AppendRecords() error: %v", err)
	}

	requests := fake.requestsFor("CreateRecord")
	if len(requests) != 1 {
		t.Fatalf("CreateRecord called %d times, want 1", len(requests))
	}
	params := requests[0].Params
	if params.Get("Proxied") != "true" || params.Get("BizName") != "web" ||
		params.Get("SourceType") != "Domain" ||
		params.Get("Data") != `{"Value":"target.example.net"}` {
		t.Fatalf("unexpected CNAME create params: %v", params)
	}
}

func TestDeleteRecords(t *testing.T) {
	fake := &fakeESA{
		t: t,
		records: []apiRecord{
			{RecordID: 1, RecordName: "_acme-challenge.example.com", RecordType: "TXT", TTL: 60, Data: apiRecordData{Value: "token"}},
			{RecordID: 2, RecordName: "_acme-challenge.example.com", RecordType: "TXT", TTL: 60, Data: apiRecordData{Value: "other"}},
			{RecordID: 3, RecordName: "www.example.com", RecordType: "A/AAAA", TTL: 600, Data: apiRecordData{Value: "192.0.2.1,2001:db8::1"}},
		},
	}
	server := httptest.NewServer(fake)
	defer server.Close()

	provider := newTestProvider(server.URL, map[string]siteInfo{"example.com": defaultTestSite()})
	deleted, err := provider.DeleteRecords(context.Background(), "example.com.", []libdns.Record{
		libdns.RR{Type: "TXT", Name: "_acme-challenge", Data: "token"},
		libdns.Address{Name: "www", IP: netip.MustParseAddr("192.0.2.1")},
	})
	if err != nil {
		t.Fatalf("DeleteRecords() error: %v", err)
	}
	if len(deleted) != 2 {
		t.Fatalf("DeleteRecords() returned %d records, want 2", len(deleted))
	}

	deletes := fake.requestsFor("DeleteRecord")
	if len(deletes) != 1 || deletes[0].Params.Get("RecordId") != "1" {
		t.Fatalf("unexpected DeleteRecord calls: %#v", deletes)
	}

	updates := fake.requestsFor("UpdateRecord")
	if len(updates) != 1 || updates[0].Params.Get("RecordId") != "3" ||
		updates[0].Params.Get("Data") != `{"Value":"2001:db8::1"}` {
		t.Fatalf("unexpected UpdateRecord calls: %#v", updates)
	}
}

func TestSetRecords(t *testing.T) {
	fake := &fakeESA{
		t: t,
		records: []apiRecord{
			{RecordID: 1, RecordName: "_acme-challenge.example.com", RecordType: "TXT", TTL: 60, Data: apiRecordData{Value: "old"}},
			{RecordID: 2, RecordName: "www.example.com", RecordType: "A/AAAA", TTL: 600, Data: apiRecordData{Value: "192.0.2.1,2001:db8::1"}},
		},
	}
	server := httptest.NewServer(fake)
	defer server.Close()

	provider := newTestProvider(server.URL, map[string]siteInfo{"example.com": defaultTestSite()})
	_, err := provider.SetRecords(context.Background(), "example.com.", []libdns.Record{
		libdns.TXT{Name: "_acme-challenge", Text: "new"},
		libdns.Address{Name: "www", IP: netip.MustParseAddr("192.0.2.2")},
	})
	if err != nil {
		t.Fatalf("SetRecords() error: %v", err)
	}

	deletes := fake.requestsFor("DeleteRecord")
	if len(deletes) != 1 || deletes[0].Params.Get("RecordId") != "1" {
		t.Fatalf("unexpected DeleteRecord calls: %#v", deletes)
	}

	updates := fake.requestsFor("UpdateRecord")
	if len(updates) != 1 || updates[0].Params.Get("RecordId") != "2" ||
		updates[0].Params.Get("Data") != `{"Value":"2001:db8::1"}` {
		t.Fatalf("unexpected UpdateRecord calls: %#v", updates)
	}

	creates := fake.requestsFor("CreateRecord")
	if len(creates) != 2 {
		t.Fatalf("CreateRecord called %d times, want 2", len(creates))
	}
	var sawTXT, sawA bool
	for _, create := range creates {
		data := create.Params.Get("Data")
		switch {
		case create.Params.Get("Type") == "TXT" && data == `{"Value":"new"}`:
			sawTXT = true
		case create.Params.Get("Type") == "A/AAAA" && data == `{"Value":"192.0.2.2"}`:
			sawA = true
		}
	}
	if !sawTXT || !sawA {
		t.Fatalf("missing expected creates: %#v", creates)
	}
}

func TestAppendDuplicateIsIdempotent(t *testing.T) {
	fake := &fakeESA{t: t, failCreateCode: "Record.RecordNameConflictWithSameRecordType"}
	server := httptest.NewServer(fake)
	defer server.Close()

	provider := newTestProvider(server.URL, map[string]siteInfo{"example.com": defaultTestSite()})
	created, err := provider.AppendRecords(context.Background(), "example.com.", []libdns.Record{
		libdns.TXT{Name: "_acme-challenge", Text: "token"},
	})
	if err != nil {
		t.Fatalf("AppendRecords() error: %v", err)
	}
	if len(created) != 1 {
		t.Fatalf("AppendRecords() returned %d records, want 1", len(created))
	}
}

func TestGetRecordsPagination(t *testing.T) {
	fake := &fakeESA{t: t}
	for i := 0; i < 501; i++ {
		fake.records = append(fake.records, apiRecord{
			RecordID:   int64(i + 1),
			RecordName: fmt.Sprintf("host%d.example.com", i),
			RecordType: "TXT",
			TTL:        60,
			Data:       apiRecordData{Value: fmt.Sprintf("value-%d", i)},
		})
	}
	server := httptest.NewServer(fake)
	defer server.Close()

	provider := newTestProvider(server.URL, map[string]siteInfo{"example.com": defaultTestSite()})
	records, err := provider.GetRecords(context.Background(), "example.com.")
	if err != nil {
		t.Fatalf("GetRecords() error: %v", err)
	}
	if len(records) != 501 {
		t.Fatalf("GetRecords() returned %d records, want 501", len(records))
	}

	requests := fake.requestsFor("ListRecords")
	if len(requests) != 2 {
		t.Fatalf("ListRecords called %d times, want 2", len(requests))
	}
	if requests[0].Params.Get("PageNumber") != "1" || requests[1].Params.Get("PageNumber") != "2" {
		t.Fatalf("unexpected pagination: %#v", requests)
	}
}

func TestDeleteRecordsWildcardAddressFamily(t *testing.T) {
	fake := &fakeESA{
		t: t,
		records: []apiRecord{
			{RecordID: 1, RecordName: "www.example.com", RecordType: "A/AAAA", TTL: 600, Data: apiRecordData{Value: "192.0.2.1,2001:db8::1"}},
		},
	}
	server := httptest.NewServer(fake)
	defer server.Close()

	provider := newTestProvider(server.URL, map[string]siteInfo{"example.com": defaultTestSite()})
	deleted, err := provider.DeleteRecords(context.Background(), "example.com.", []libdns.Record{
		libdns.RR{Type: "A", Name: "www"},
	})
	if err != nil {
		t.Fatalf("DeleteRecords() error: %v", err)
	}
	if len(deleted) != 1 {
		t.Fatalf("DeleteRecords() returned %d records, want 1", len(deleted))
	}

	updates := fake.requestsFor("UpdateRecord")
	if len(updates) != 1 || updates[0].Params.Get("RecordId") != "1" ||
		updates[0].Params.Get("Data") != `{"Value":"2001:db8::1"}` {
		t.Fatalf("unexpected UpdateRecord calls: %#v", updates)
	}
}

func TestGenericURIConversion(t *testing.T) {
	provider := newTestProvider("http://example.invalid", nil)
	site := defaultTestSite()

	in, err := provider.recordInput(
		libdns.RR{Type: "URI", Name: "_http._tcp", Data: `10 5 "https://example.com/path"`},
		"example.com.", site,
	)
	if err != nil {
		t.Fatalf("recordInput() error: %v", err)
	}
	if in.Type != "URI" || in.Name != "_http._tcp.example.com" ||
		in.Data.Value != "https://example.com/path" ||
		in.Data.Priority == nil || *in.Data.Priority != 10 ||
		in.Data.Weight == nil || *in.Data.Weight != 5 {
		t.Fatalf("unexpected URI input: %#v", in)
	}

	records := apiRecordToLibDNS(apiRecord{
		RecordName: "_http._tcp.example.com",
		RecordType: "URI",
		TTL:        600,
		Data: apiRecordData{
			Value:    "https://example.com/path",
			Priority: 10,
			Weight:   5,
		},
	}, "_http._tcp.example.com", "example.com")
	if len(records) != 1 {
		t.Fatalf("apiRecordToLibDNS() returned %d records, want 1", len(records))
	}
	rr := records[0].RR()
	if rr.Type != "URI" || rr.Name != "_http._tcp" ||
		rr.Data != `10 5 "https://example.com/path"` {
		t.Fatalf("unexpected URI record: %#v", rr)
	}
}

func TestListZones(t *testing.T) {
	fake := &fakeESA{
		t: t,
		sites: []siteInfo{
			{SiteID: 2, SiteName: "b.example.com", AccessType: "NS"},
			{SiteID: 1, SiteName: "a.example.com", AccessType: "NS"},
		},
	}
	server := httptest.NewServer(fake)
	defer server.Close()

	provider := newTestProvider(server.URL, nil)
	zones, err := provider.ListZones(context.Background())
	if err != nil {
		t.Fatalf("ListZones() error: %v", err)
	}
	if len(zones) != 2 || zones[0].Name != "a.example.com." || zones[1].Name != "b.example.com." {
		t.Fatalf("unexpected zones: %#v", zones)
	}
}
