package aliesa

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/libdns/libdns"
)

// GetRecords returns all records in the given zone.
func (p *Provider) GetRecords(ctx context.Context, zone string) ([]libdns.Record, error) {
	site, err := p.siteForZone(ctx, zone)
	if err != nil {
		return nil, err
	}

	records, err := p.client.listAllRecords(ctx, site.SiteID)
	if err != nil {
		return nil, err
	}

	zoneName := normalizeZone(zone)
	out := make([]libdns.Record, 0, len(records))
	for _, record := range records {
		abs := apiRecordAbsoluteName(record.RecordName, site.SiteName)
		if !nameInZone(abs, zoneName) {
			continue
		}
		out = append(out, apiRecordToLibDNS(record, abs, zoneName)...)
	}

	sortRecords(out)
	return out, nil
}

// AppendRecords creates the given records. It never modifies existing records.
func (p *Provider) AppendRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	site, err := p.siteForZone(ctx, zone)
	if err != nil {
		return nil, err
	}
	p.state.writeMu.Lock()
	defer p.state.writeMu.Unlock()

	created := make([]libdns.Record, 0, len(recs))
	for _, rec := range recs {
		in, err := p.recordInput(rec, zone, site)
		if err != nil {
			return created, err
		}
		if _, err := p.client.createRecord(ctx, in); err != nil {
			// ACME challenges can race with cleanup. An exact duplicate is
			// already the desired end state, so treat it as success.
			if isDuplicateRecordError(err) {
				created = append(created, rec)
				continue
			}
			return created, fmt.Errorf("aliesa: create %s record %q: %w", in.Type, in.Name, err)
		}
		created = append(created, rec)
	}

	return created, nil
}

// SetRecords makes the input records the only records for each (name, type)
// pair. ESA has no batch transaction, so this is not atomic: matching records
// are removed and then the requested records are created.
func (p *Provider) SetRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	site, err := p.siteForZone(ctx, zone)
	if err != nil {
		return nil, err
	}
	p.state.writeMu.Lock()
	defer p.state.writeMu.Unlock()

	zoneName := normalizeZone(zone)
	type recordGroup struct {
		abs     string
		apiType string
		family  string
		records []libdns.Record
	}

	groups := make(map[string]*recordGroup)
	var order []string
	for _, rec := range recs {
		in, err := p.recordInput(rec, zone, site)
		if err != nil {
			return nil, err
		}
		rr := rec.RR()
		family := ""
		if in.Type == "A/AAAA" {
			family = strings.ToUpper(rr.Type)
			if family != "A" && family != "AAAA" {
				family = ""
			}
		}
		key := in.Name + "|" + in.Type + "|" + family
		group := groups[key]
		if group == nil {
			group = &recordGroup{
				abs:     absoluteRecordName(rr.Name, zoneName),
				apiType: in.Type,
				family:  family,
			}
			groups[key] = group
			order = append(order, key)
		}
		group.records = append(group.records, rec)
	}

	sort.Strings(order)

	var records []apiRecord
	fetched := make(map[string]bool)
	seen := make(map[int64]bool)
	for _, key := range order {
		group := groups[key]
		if fetched[group.abs] {
			continue
		}
		fetched[group.abs] = true
		groupRecords, err := p.listRecordsForName(ctx, site, group.abs)
		if err != nil {
			return nil, err
		}
		for _, record := range groupRecords {
			if record.RecordID != 0 && seen[record.RecordID] {
				continue
			}
			seen[record.RecordID] = true
			records = append(records, record)
		}
	}

	for _, key := range order {
		group := groups[key]
		if err := p.deleteRecordGroup(ctx, site, &records, group.abs, group.apiType, group.family); err != nil {
			return nil, err
		}
		for _, rec := range group.records {
			in, err := p.recordInput(rec, zone, site)
			if err != nil {
				return nil, err
			}
			if _, err := p.client.createRecord(ctx, in); err != nil {
				return nil, fmt.Errorf("aliesa: set %s record %q: %w", in.Type, in.Name, err)
			}
		}
	}

	return recs, nil
}

// DeleteRecords deletes records that exactly match the input. A wildcard
// match is allowed when the input's type, data, or TTL is empty.
func (p *Provider) DeleteRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	site, err := p.siteForZone(ctx, zone)
	if err != nil {
		return nil, err
	}
	p.state.writeMu.Lock()
	defer p.state.writeMu.Unlock()

	zoneName := normalizeZone(zone)
	recordsByName := make(map[string][]apiRecord)
	deleted := make([]libdns.Record, 0, len(recs))
	for _, rec := range recs {
		want := rec.RR()
		abs := absoluteRecordName(want.Name, zoneName)
		if !nameInZone(abs, zoneName) {
			continue
		}

		records, ok := recordsByName[abs]
		if !ok {
			records, err = p.listRecordsForName(ctx, site, abs)
			if err != nil {
				return deleted, err
			}
		}

		// An empty value on an A or AAAA deletion means "all addresses of
		// that family", not "delete the whole combined A/AAAA record".
		family := ""
		if want.Data == "" {
			switch strings.ToUpper(want.Type) {
			case "A", "AAAA":
				family = strings.ToUpper(want.Type)
			}
		}

		matched := false
		for i := range records {
			record := &records[i]
			if record.RecordID == 0 {
				continue
			}
			recordAbs := apiRecordAbsoluteName(record.RecordName, site.SiteName)
			if !strings.EqualFold(recordAbs, abs) {
				continue
			}
			if !apiTypeMatches(want.Type, record.RecordType) {
				continue
			}

			converted := apiRecordToLibDNS(*record, recordAbs, zoneName)
			ok, matchedValue := findMatchingRecord(converted, want)
			if !ok {
				continue
			}

			switch {
			case matchedValue != "":
				remaining := removeValue(splitValues(record.Data.Value), matchedValue)
				if len(remaining) == 0 {
					if err := p.client.deleteRecord(ctx, record.RecordID); err != nil {
						return deleted, fmt.Errorf("aliesa: delete record %d: %w", record.RecordID, err)
					}
					record.RecordID = 0
				} else {
					value := strings.Join(remaining, ",")
					if err := p.updateRecordValue(ctx, record, value); err != nil {
						return deleted, err
					}
					record.Data.Value = value
				}
			case family != "":
				values := splitValues(record.Data.Value)
				remaining := filterAddressFamily(values, family, false)
				if len(remaining) == len(values) {
					continue
				}
				if len(remaining) == 0 {
					if err := p.client.deleteRecord(ctx, record.RecordID); err != nil {
						return deleted, fmt.Errorf("aliesa: delete record %d: %w", record.RecordID, err)
					}
					record.RecordID = 0
				} else {
					value := strings.Join(remaining, ",")
					if err := p.updateRecordValue(ctx, record, value); err != nil {
						return deleted, err
					}
					record.Data.Value = value
				}
			default:
				if err := p.client.deleteRecord(ctx, record.RecordID); err != nil {
					return deleted, fmt.Errorf("aliesa: delete record %d: %w", record.RecordID, err)
				}
				record.RecordID = 0
			}

			matched = true
		}

		recordsByName[abs] = records
		if matched {
			deleted = append(deleted, rec)
		}
	}

	return deleted, nil
}

// ListZones returns all ESA sites as DNS zones.
func (p *Provider) ListZones(ctx context.Context) ([]libdns.Zone, error) {
	sites, err := p.client.listAllSites(ctx, "", "")
	if err != nil {
		return nil, err
	}

	zones := make([]libdns.Zone, 0, len(sites))
	for _, site := range sites {
		name := normalizeSiteName(site.SiteName)
		if name == "" {
			continue
		}
		zones = append(zones, libdns.Zone{Name: name + "."})
	}
	sort.Slice(zones, func(i, j int) bool { return zones[i].Name < zones[j].Name })
	return zones, nil
}

func (p *Provider) siteForZone(ctx context.Context, zone string) (siteInfo, error) {
	zoneName := normalizeZone(zone)
	if zoneName == "" {
		return siteInfo{}, errors.New("aliesa: zone is empty")
	}

	state := p.state
	if state == nil {
		state = &providerState{siteCache: make(map[string]siteInfo)}
		p.state = state
	}

	state.mu.Lock()
	site, ok := state.siteCache[zoneName]
	state.mu.Unlock()
	if ok {
		return site, nil
	}

	site, err := p.resolveSite(ctx, zoneName)
	if err != nil {
		return siteInfo{}, err
	}

	state.mu.Lock()
	if state.siteCache == nil {
		state.siteCache = make(map[string]siteInfo)
	}
	state.siteCache[zoneName] = site
	state.mu.Unlock()

	return site, nil
}

func (p *Provider) listRecordsForName(ctx context.Context, site siteInfo, abs string) ([]apiRecord, error) {
	// The exact name filter is well defined for ordinary host records. For
	// the site apex, also tolerate APIs that expect "@" when filtering by
	// listing the site and matching locally.
	if abs == normalizeSiteName(site.SiteName) {
		return p.client.listAllRecords(ctx, site.SiteID)
	}
	return p.client.listAllRecordsByName(ctx, site.SiteID, abs)
}

func (p *Provider) resolveSite(ctx context.Context, zone string) (siteInfo, error) {
	sites, err := p.client.listAllSites(ctx, zone, "exact")
	if err != nil {
		return siteInfo{}, err
	}
	for _, site := range sites {
		if normalizeSiteName(site.SiteName) == zone {
			return normalizeSite(site), nil
		}
	}

	// A zone managed by Caddy can also be a delegated subdomain of an ESA
	// site. Match the longest site suffix in that case.
	allSites, err := p.client.listAllSites(ctx, "", "")
	if err != nil {
		return siteInfo{}, err
	}

	var best siteInfo
	found := false
	for _, site := range allSites {
		siteName := normalizeSiteName(site.SiteName)
		if siteName == "" {
			continue
		}
		if zone == siteName || strings.HasSuffix(zone, "."+siteName) {
			if !found || len(siteName) > len(normalizeSiteName(best.SiteName)) {
				best = site
				found = true
			}
		}
	}
	if !found {
		return siteInfo{}, fmt.Errorf("aliesa: no ESA site found for zone %q", zone)
	}
	return normalizeSite(best), nil
}

func normalizeSite(site siteInfo) siteInfo {
	site.SiteName = normalizeSiteName(site.SiteName)
	return site
}

func normalizeZone(zone string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(zone), "."))
}

func normalizeSiteName(name string) string {
	return normalizeZone(name)
}

func nameInZone(name, zone string) bool {
	name = normalizeSiteName(name)
	zone = normalizeZone(zone)
	return name == zone || strings.HasSuffix(name, "."+zone)
}

func apiRecordAbsoluteName(recordName, siteName string) string {
	siteName = normalizeSiteName(siteName)
	name := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(recordName), "."))
	switch {
	case name == "" || name == "@":
		return siteName
	case siteName != "" && (name == siteName || strings.HasSuffix(name, "."+siteName)):
		return name
	case siteName != "" && !strings.Contains(name, "."):
		return name + "." + siteName
	default:
		return name
	}
}

func absoluteRecordName(name, zone string) string {
	zone = normalizeZone(zone)
	name = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
	if name == "" || name == "@" {
		return zone
	}
	if name == zone || strings.HasSuffix(name, "."+zone) {
		return name
	}
	return name + "." + zone
}

func apiRecordName(abs, siteName string) string {
	if abs == normalizeSiteName(siteName) {
		return "@"
	}
	return abs
}

func relativeRecordName(abs, zone string) string {
	return libdns.RelativeName(abs+".", normalizeZone(zone)+".")
}

func splitValues(value string) []string {
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func removeValue(values []string, value string) []string {
	out := make([]string, 0, len(values))
	for _, item := range values {
		if !strings.EqualFold(item, value) {
			out = append(out, item)
		}
	}
	return out
}

func filterAddressFamily(values []string, family string, keep bool) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		ip, err := netip.ParseAddr(value)
		isFamily := err == nil &&
			((family == "A" && ip.Is4()) || (family == "AAAA" && ip.Is6()))
		if isFamily == keep {
			out = append(out, value)
		}
	}
	return out
}

func apiTypeMatches(inputType, apiType string) bool {
	inputType = strings.ToUpper(strings.TrimSpace(inputType))
	apiType = strings.ToUpper(strings.TrimSpace(apiType))
	if inputType == "" {
		return true
	}
	switch inputType {
	case "A", "AAAA", "A/AAAA":
		return apiType == "A/AAAA" || apiType == "A" || apiType == "AAAA"
	}
	return inputType == apiType
}

func recordTypeMatches(a, b string) bool {
	return strings.EqualFold(strings.TrimSpace(a), strings.TrimSpace(b))
}

func canonicalRecordData(rr libdns.RR) string {
	switch strings.ToUpper(rr.Type) {
	case "TXT":
		return rr.Data
	case "CAA", "URI":
		return strings.TrimSpace(rr.Data)
	default:
		return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(rr.Data), "."))
	}
}

func findMatchingRecord(converted []libdns.Record, want libdns.RR) (bool, string) {
	for _, rec := range converted {
		got := rec.RR()
		if !strings.EqualFold(got.Name, want.Name) {
			continue
		}
		if want.Type != "" && !recordTypeMatches(want.Type, got.Type) {
			continue
		}
		if want.TTL > 0 && got.TTL != want.TTL {
			continue
		}
		if want.Data != "" {
			if strings.EqualFold(got.Type, "TXT") {
				if got.Data != want.Data {
					continue
				}
			} else if canonicalRecordData(got) != canonicalRecordData(want) {
				continue
			}
		}
		if want.Data != "" && (strings.EqualFold(got.Type, "A") || strings.EqualFold(got.Type, "AAAA")) {
			return true, got.Data
		}
		return true, ""
	}
	return false, ""
}

func apiWriteType(recordType string) string {
	recordType = strings.ToUpper(strings.TrimSpace(recordType))
	switch recordType {
	case "A", "AAAA", "A/AAAA":
		return "A/AAAA"
	default:
		return recordType
	}
}

func (p *Provider) updateRecordValue(ctx context.Context, record *apiRecord, value string) error {
	in := recordInput{
		SiteID: record.SiteID,
		Name:   apiRecordAbsoluteName(record.RecordName, record.SiteName),
		Type:   apiWriteType(record.RecordType),
		TTL:    record.TTL,
		Data:   apiRecordDataInput{Value: value},
	}
	if strings.EqualFold(record.RecordType, "A/AAAA") || strings.EqualFold(record.RecordType, "CNAME") {
		in.Proxied = boolPtr(record.Proxied)
		if record.Proxied {
			in.BizName = p.BizName
		}
	}
	if strings.EqualFold(record.RecordType, "CNAME") {
		in.SourceType = "Domain"
	}
	if err := p.client.updateRecord(ctx, record.RecordID, in); err != nil {
		return fmt.Errorf("aliesa: update record %d: %w", record.RecordID, err)
	}
	return nil
}

func (p *Provider) deleteRecordGroup(ctx context.Context, site siteInfo, records *[]apiRecord, abs, apiType, family string) error {
	for i := range *records {
		record := &(*records)[i]
		if record.RecordID == 0 {
			continue
		}
		recordAbs := apiRecordAbsoluteName(record.RecordName, site.SiteName)
		if !strings.EqualFold(recordAbs, abs) {
			continue
		}
		if !apiTypeMatches(apiType, record.RecordType) {
			continue
		}

		if family == "" {
			if err := p.client.deleteRecord(ctx, record.RecordID); err != nil {
				return fmt.Errorf("aliesa: delete record %d: %w", record.RecordID, err)
			}
			record.RecordID = 0
			continue
		}

		values := splitValues(record.Data.Value)
		remaining := filterAddressFamily(values, family, false)
		if len(remaining) == len(values) {
			continue
		}
		if len(remaining) == 0 {
			if err := p.client.deleteRecord(ctx, record.RecordID); err != nil {
				return fmt.Errorf("aliesa: delete record %d: %w", record.RecordID, err)
			}
			record.RecordID = 0
			continue
		}
		value := strings.Join(remaining, ",")
		if err := p.updateRecordValue(ctx, record, value); err != nil {
			return err
		}
		record.Data.Value = value
	}
	return nil
}

func (p *Provider) recordInput(rec libdns.Record, zone string, site siteInfo) (recordInput, error) {
	rr := rec.RR()
	if generic, ok := rec.(libdns.RR); ok {
		parsed, _ := generic.Parse()
		if _, stillGeneric := parsed.(libdns.RR); !stillGeneric {
			rec = parsed
			rr = rec.RR()
		}
	}

	abs := absoluteRecordName(rr.Name, zone)
	in := recordInput{
		SiteID: site.SiteID,
		Name:   apiRecordName(abs, site.SiteName),
		TTL:    p.apiTTL(rr.TTL),
	}

	switch value := rec.(type) {
	case libdns.Address:
		if !value.IP.IsValid() {
			return in, errors.New("aliesa: address record has no IP")
		}
		in.Type = "A/AAAA"
		in.Data.Value = value.IP.String()
		in.Proxied = p.proxiedFor(site, in.Type)

	case libdns.CNAME:
		in.Type = "CNAME"
		in.Data.Value = trimDot(value.Target)
		in.SourceType = "Domain"
		in.Proxied = p.proxiedFor(site, in.Type)

	case libdns.TXT:
		in.Type = "TXT"
		in.Data.Value = value.Text

	case libdns.MX:
		in.Type = "MX"
		in.Data.Value = trimDot(value.Target)
		in.Data.Priority = int32Ptr(int32(value.Preference))

	case libdns.NS:
		in.Type = "NS"
		in.Data.Value = trimDot(value.Target)

	case libdns.SRV:
		in.Type = "SRV"
		in.Data.Value = trimDot(value.Target)
		in.Data.Priority = int32Ptr(int32(value.Priority))
		in.Data.Weight = int32Ptr(int32(value.Weight))
		in.Data.Port = int32Ptr(int32(value.Port))

	case libdns.CAA:
		in.Type = "CAA"
		in.Data.Value = value.Value
		in.Data.Flag = int32Ptr(int32(value.Flags))
		in.Data.Tag = value.Tag

	case libdns.ServiceBinding:
		return in, fmt.Errorf("aliesa: record type %s is not supported by ESA", rr.Type)

	case libdns.RR:
		if err := p.fillGenericInput(&in, value); err != nil {
			return in, err
		}
		if in.Type == "A/AAAA" {
			in.Proxied = p.proxiedFor(site, in.Type)
		}
		if in.Type == "CNAME" {
			in.SourceType = "Domain"
			in.Proxied = p.proxiedFor(site, in.Type)
		}

	default:
		return in, fmt.Errorf("aliesa: record type %T (%s) is not supported", rec, rr.Type)
	}

	if in.Proxied != nil && *in.Proxied && in.BizName == "" {
		in.BizName = p.BizName
	}
	if in.Proxied != nil && !*in.Proxied {
		in.BizName = ""
	}

	return in, nil
}

func (p *Provider) fillGenericInput(in *recordInput, rr libdns.RR) error {
	switch strings.ToUpper(rr.Type) {
	case "A", "AAAA", "A/AAAA":
		ip, err := netip.ParseAddr(strings.TrimSpace(rr.Data))
		if err != nil {
			return fmt.Errorf("aliesa: invalid %s record value %q: %w", rr.Type, rr.Data, err)
		}
		in.Type = "A/AAAA"
		in.Data.Value = ip.String()

	case "CNAME":
		in.Type = "CNAME"
		in.Data.Value = trimDot(rr.Data)
		in.SourceType = "Domain"

	case "TXT":
		in.Type = "TXT"
		in.Data.Value = rr.Data

	case "MX":
		fields := strings.Fields(rr.Data)
		if len(fields) != 2 {
			return fmt.Errorf("aliesa: malformed MX record data %q", rr.Data)
		}
		priority, err := strconv.ParseUint(fields[0], 10, 16)
		if err != nil {
			return fmt.Errorf("aliesa: invalid MX priority %q: %w", fields[0], err)
		}
		in.Type = "MX"
		in.Data.Value = trimDot(fields[1])
		in.Data.Priority = int32Ptr(int32(priority))

	case "NS":
		in.Type = "NS"
		in.Data.Value = trimDot(rr.Data)

	case "PTR":
		in.Type = "PTR"
		in.Data.Value = trimDot(rr.Data)

	case "SRV":
		fields := strings.Fields(rr.Data)
		if len(fields) != 4 {
			return fmt.Errorf("aliesa: malformed SRV record data %q", rr.Data)
		}
		priority, err := parseUint16(fields[0])
		if err != nil {
			return fmt.Errorf("aliesa: invalid SRV priority %q: %w", fields[0], err)
		}
		weight, err := parseUint16(fields[1])
		if err != nil {
			return fmt.Errorf("aliesa: invalid SRV weight %q: %w", fields[1], err)
		}
		port, err := parseUint16(fields[2])
		if err != nil {
			return fmt.Errorf("aliesa: invalid SRV port %q: %w", fields[2], err)
		}
		in.Type = "SRV"
		in.Data.Value = trimDot(fields[3])
		in.Data.Priority = int32Ptr(int32(priority))
		in.Data.Weight = int32Ptr(int32(weight))
		in.Data.Port = int32Ptr(int32(port))

	case "CAA":
		fields := strings.SplitN(rr.Data, " ", 3)
		if len(fields) != 3 {
			return fmt.Errorf("aliesa: malformed CAA record data %q", rr.Data)
		}
		flags, err := strconv.ParseUint(fields[0], 10, 8)
		if err != nil {
			return fmt.Errorf("aliesa: invalid CAA flags %q: %w", fields[0], err)
		}
		value := strings.TrimSpace(fields[2])
		if unquoted, err := strconv.Unquote(value); err == nil {
			value = unquoted
		}
		in.Type = "CAA"
		in.Data.Value = value
		in.Data.Flag = int32Ptr(int32(flags))
		in.Data.Tag = fields[1]

	case "URI":
		fields := strings.Fields(rr.Data)
		if len(fields) != 3 {
			return fmt.Errorf("aliesa: malformed URI record data %q", rr.Data)
		}
		priority, err := parseUint16(fields[0])
		if err != nil {
			return fmt.Errorf("aliesa: invalid URI priority %q: %w", fields[0], err)
		}
		weight, err := parseUint16(fields[1])
		if err != nil {
			return fmt.Errorf("aliesa: invalid URI weight %q: %w", fields[1], err)
		}
		value := fields[2]
		if unquoted, err := strconv.Unquote(value); err == nil {
			value = unquoted
		}
		in.Type = "URI"
		in.Data.Value = value
		in.Data.Priority = int32Ptr(int32(priority))
		in.Data.Weight = int32Ptr(int32(weight))

	case "CERT":
		fields := strings.Fields(rr.Data)
		if len(fields) != 4 {
			return fmt.Errorf("aliesa: malformed CERT record data %q", rr.Data)
		}
		typeValue, err := parseUint16(fields[0])
		if err != nil {
			return err
		}
		keyTag, err := parseUint16(fields[1])
		if err != nil {
			return err
		}
		algorithm, err := parseUint16(fields[2])
		if err != nil {
			return err
		}
		in.Type = "CERT"
		in.Data.Type = int32Ptr(int32(typeValue))
		in.Data.KeyTag = int32Ptr(int32(keyTag))
		in.Data.Algorithm = int32Ptr(int32(algorithm))
		in.Data.Certificate = fields[3]

	case "SSHFP":
		fields := strings.Fields(rr.Data)
		if len(fields) != 3 {
			return fmt.Errorf("aliesa: malformed SSHFP record data %q", rr.Data)
		}
		algorithm, err := parseUint16(fields[0])
		if err != nil {
			return err
		}
		typeValue, err := parseUint16(fields[1])
		if err != nil {
			return err
		}
		in.Type = "SSHFP"
		in.Data.Algorithm = int32Ptr(int32(algorithm))
		in.Data.Type = int32Ptr(int32(typeValue))
		in.Data.Fingerprint = fields[2]

	case "SMIMEA", "TLSA":
		fields := strings.Fields(rr.Data)
		if len(fields) != 4 {
			return fmt.Errorf("aliesa: malformed %s record data %q", rr.Type, rr.Data)
		}
		usage, err := parseUint16(fields[0])
		if err != nil {
			return err
		}
		selector, err := parseUint16(fields[1])
		if err != nil {
			return err
		}
		matchingType, err := parseUint16(fields[2])
		if err != nil {
			return err
		}
		in.Type = strings.ToUpper(rr.Type)
		in.Data.Usage = int32Ptr(int32(usage))
		in.Data.Selector = int32Ptr(int32(selector))
		in.Data.MatchingType = int32Ptr(int32(matchingType))
		in.Data.Certificate = fields[3]

	default:
		in.Type = strings.ToUpper(rr.Type)
		in.Data.Value = rr.Data
	}

	return nil
}

func parseUint16(value string) (uint16, error) {
	v, err := strconv.ParseUint(value, 10, 16)
	return uint16(v), err
}

func trimDot(value string) string {
	return strings.TrimSuffix(strings.TrimSpace(value), ".")
}

func dotTarget(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || value == "." || strings.HasSuffix(value, ".") {
		return value
	}
	return value + "."
}

func (p *Provider) apiTTL(ttl time.Duration) int64 {
	if ttl <= 0 {
		if p.TTL > 0 {
			return int64(p.TTL)
		}
		return defaultTTL
	}
	seconds := int64(ttl / time.Second)
	if seconds <= 1 {
		return 1
	}
	if seconds < minTTL {
		seconds = minTTL
	}
	if seconds > maxTTL {
		seconds = maxTTL
	}
	return seconds
}

func (p *Provider) proxiedFor(site siteInfo, apiType string) *bool {
	if apiType != "A/AAAA" && apiType != "CNAME" {
		return nil
	}
	if p.Proxied != nil {
		return boolPtr(*p.Proxied)
	}
	return boolPtr(strings.EqualFold(site.AccessType, "CNAME"))
}

func apiTTLToDuration(ttl int64) time.Duration {
	if ttl <= 1 {
		return 0
	}
	return time.Duration(ttl) * time.Second
}

func sortRecords(records []libdns.Record) {
	sort.SliceStable(records, func(i, j int) bool {
		a := records[i].RR()
		b := records[j].RR()
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		if a.Type != b.Type {
			return a.Type < b.Type
		}
		return a.Data < b.Data
	})
}

func apiRecordToLibDNS(record apiRecord, abs, zone string) []libdns.Record {
	name := relativeRecordName(abs, zone)
	ttl := apiTTLToDuration(record.TTL)
	recordType := strings.ToUpper(strings.TrimSpace(record.RecordType))

	switch recordType {
	case "A", "AAAA", "A/AAAA":
		values := splitValues(record.Data.Value)
		out := make([]libdns.Record, 0, len(values))
		for _, value := range values {
			ip, err := netip.ParseAddr(value)
			if err != nil {
				out = append(out, libdns.RR{Name: name, TTL: ttl, Type: "A/AAAA", Data: value})
				continue
			}
			out = append(out, libdns.Address{Name: name, TTL: ttl, IP: ip})
		}
		return out

	case "CNAME":
		return []libdns.Record{libdns.CNAME{Name: name, TTL: ttl, Target: dotTarget(record.Data.Value)}}

	case "TXT":
		return []libdns.Record{libdns.TXT{Name: name, TTL: ttl, Text: record.Data.Value}}

	case "MX":
		return []libdns.Record{libdns.MX{
			Name:       name,
			TTL:        ttl,
			Preference: uint16(record.Data.Priority),
			Target:     dotTarget(record.Data.Value),
		}}

	case "NS":
		return []libdns.Record{libdns.NS{Name: name, TTL: ttl, Target: dotTarget(record.Data.Value)}}

	case "SRV":
		service, transport, srvName, ok := parseSRVName(name)
		if !ok {
			return []libdns.Record{libdns.RR{
				Name: name,
				TTL:  ttl,
				Type: "SRV",
				Data: fmt.Sprintf("%d %d %d %s", record.Data.Priority, record.Data.Weight, record.Data.Port, record.Data.Value),
			}}
		}
		return []libdns.Record{libdns.SRV{
			Service:   service,
			Transport: transport,
			Name:      srvName,
			TTL:       ttl,
			Priority:  uint16(record.Data.Priority),
			Weight:    uint16(record.Data.Weight),
			Port:      uint16(record.Data.Port),
			Target:    dotTarget(record.Data.Value),
		}}

	case "CAA":
		return []libdns.Record{libdns.CAA{
			Name:  name,
			TTL:   ttl,
			Flags: uint8(record.Data.Flag),
			Tag:   record.Data.Tag,
			Value: record.Data.Value,
		}}

	case "URI":
		return []libdns.Record{libdns.RR{
			Name: name,
			TTL:  ttl,
			Type: "URI",
			Data: fmt.Sprintf("%d %d %q", record.Data.Priority, record.Data.Weight, record.Data.Value),
		}}

	case "PTR":
		return []libdns.Record{libdns.RR{Name: name, TTL: ttl, Type: "PTR", Data: dotTarget(record.Data.Value)}}

	case "CERT":
		return []libdns.Record{libdns.RR{
			Name: name,
			TTL:  ttl,
			Type: "CERT",
			Data: fmt.Sprintf("%d %d %d %s", record.Data.Type, record.Data.KeyTag, record.Data.Algorithm, record.Data.Certificate),
		}}

	case "SSHFP":
		return []libdns.Record{libdns.RR{
			Name: name,
			TTL:  ttl,
			Type: "SSHFP",
			Data: fmt.Sprintf("%d %d %s", record.Data.Algorithm, record.Data.Type, record.Data.Fingerprint),
		}}

	case "SMIMEA", "TLSA":
		return []libdns.Record{libdns.RR{
			Name: name,
			TTL:  ttl,
			Type: recordType,
			Data: fmt.Sprintf("%d %d %d %s", record.Data.Usage, record.Data.Selector, record.Data.MatchingType, record.Data.Certificate),
		}}

	default:
		return []libdns.Record{libdns.RR{Name: name, TTL: ttl, Type: recordType, Data: record.Data.Value}}
	}
}

func parseSRVName(name string) (service, transport, srvName string, ok bool) {
	parts := strings.Split(name, ".")
	if len(parts) < 2 {
		return "", "", "", false
	}
	if !strings.HasPrefix(parts[0], "_") || !strings.HasPrefix(parts[1], "_") {
		return "", "", "", false
	}
	service = strings.TrimPrefix(parts[0], "_")
	transport = strings.TrimPrefix(parts[1], "_")
	if len(parts) == 2 {
		srvName = "@"
	} else {
		srvName = strings.Join(parts[2:], ".")
	}
	return service, transport, srvName, true
}

func isDuplicateRecordError(err error) bool {
	var apiErr *apiError
	if errors.As(err, &apiErr) {
		return apiErr.Code == "Record.RecordNameConflictWithSameRecordType"
	}
	return false
}
