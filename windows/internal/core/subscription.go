package core

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf16"
)

type ParsedSubscription struct {
	NodeCount       int
	ProviderContent string
}

var (
	ErrInvalidSubscriptionURL   = errors.New("订阅链接无效，只支持 http/https")
	ErrEmptySubscription        = errors.New("订阅返回了空内容")
	ErrUnrecognizedSubscription = errors.New("无法识别订阅格式（需要 Clash YAML 或节点链接列表）")
	ErrNoSubscriptionNodes      = errors.New("订阅里没有可用节点")
)

func SubscriptionHTTPError(code int) error {
	return fmt.Errorf("订阅服务器返回 HTTP %d", code)
}

var subscriptionSchemes = []string{
	"ss://", "ssr://", "vmess://", "vless://", "trojan://", "hysteria://", "hysteria2://",
	"hy2://", "tuic://", "anytls://", "wireguard://", "wg://", "socks5://", "socks://", "snell://",
}

var uriHostname = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)*\.?$`)

func parseSubscriptionURL(raw string) (*url.URL, string) {
	if strings.ContainsAny(raw, "\"<>\\^`{|}") || strings.IndexFunc(raw, func(r rune) bool {
		return unicode.IsSpace(r) || unicode.IsControl(r)
	}) >= 0 {
		return nil, ""
	}
	authority, path := rawURLParts(raw)
	if strings.ContainsAny(path, "[]") {
		return nil, ""
	}
	rawHost := authority[strings.LastIndexByte(authority, '@')+1:]
	parseInput := raw
	if strings.HasPrefix(rawHost, "[") {
		// java.net.URI accepts a literal percent in an IPv6 scope identifier
		if scope := strings.IndexByte(rawHost, '%'); scope >= 0 && !strings.HasPrefix(rawHost[scope:], "%25") {
			rawScope := rawHost[:scope] + "%25" + rawHost[scope+1:]
			at := strings.Index(raw, "//") + 2 + len(authority) - len(rawHost)
			parseInput = raw[:at] + rawScope + raw[at+len(rawHost):]
		}
	}
	u, err := url.Parse(parseInput)
	if err != nil || u.Hostname() == "" {
		return nil, ""
	}
	if port := u.Port(); port != "" {
		if _, err := strconv.ParseInt(port, 10, 32); err != nil {
			return nil, ""
		}
	}
	host := u.Hostname()
	if strings.HasPrefix(u.Host, "[") {
		if end := strings.IndexByte(rawHost, ']'); end >= 0 {
			if addr, err := netip.ParseAddr(host); err == nil && addr.Is6() {
				return u, rawHost[:end+1]
			}
		}
		return nil, ""
	}
	if !uriHostname.MatchString(host) {
		return nil, ""
	}
	domain := strings.TrimSuffix(host, ".")
	if i := strings.LastIndexByte(domain, '.'); i >= 0 && domain[i+1] >= '0' && domain[i+1] <= '9' {
		// a numeric final label requires a dotted quad, including zero-padded octets
		octets := strings.Split(host, ".")
		if len(octets) != 4 {
			return nil, ""
		}
		for _, octet := range octets {
			if _, err := strconv.ParseUint(octet, 10, 8); err != nil {
				return nil, ""
			}
		}
	}
	return u, host
}

func rawURLParts(raw string) (string, string) {
	_, rest, _ := strings.Cut(raw, "//")
	if i := strings.IndexAny(rest, "?#"); i >= 0 {
		rest = rest[:i]
	}
	if i := strings.IndexByte(rest, '/'); i >= 0 {
		return rest[:i], rest[i:]
	}
	return rest, ""
}

func ValidateSubscriptionURL(raw string) *url.URL {
	u, _ := parseSubscriptionURL(strings.TrimSpace(raw))
	if u == nil || (u.Scheme != "https" && u.Scheme != "http") {
		return nil
	}
	return u
}

func ParseSubscription(data []byte) (ParsedSubscription, error) {
	text := strings.TrimSpace(strings.ToValidUTF8(string(data), "\uFFFD"))
	if text == "" {
		return ParsedSubscription{}, ErrEmptySubscription
	}
	if p, ok := ParseClashYAML(text); ok {
		return p, nil
	}
	if p, ok := ParseURIList(text); ok {
		return p, nil
	}
	if decoded, ok := DecodeSubscriptionBase64(text); ok {
		if p, ok := ParseURIList(decoded); ok {
			return p, nil
		}
	}
	return ParsedSubscription{}, ErrUnrecognizedSubscription
}

func lines(text string) []string {
	return strings.Split(strings.ReplaceAll(strings.ReplaceAll(text, "\r\n", "\n"), "\r", "\n"), "\n")
}

func ParseClashYAML(text string) (ParsedSubscription, bool) {
	all := lines(text)
	for i, line := range all {
		if !strings.HasPrefix(line, "proxies:") {
			continue
		}
		count, end := 0, i+1
		for ; end < len(all); end++ {
			next := all[end]
			if next != "" && next[0] != '-' && next[0] != '#' && len(strings.TrimLeftFunc(next, unicode.IsSpace)) == len(next) {
				break
			}
			t := strings.TrimSpace(next)
			if strings.HasPrefix(t, "- {") || strings.HasPrefix(t, "-{") || strings.HasPrefix(t, "- name:") {
				count++
			}
		}
		if count == 0 && strings.Contains(line, "[") {
			count = strings.Count(line, "name:")
		}
		if count > 0 {
			return ParsedSubscription{count, strings.Join(all[i:end], "\n") + "\n"}, true
		}
		break
	}
	return ParsedSubscription{}, false
}

func isSubscriptionScheme(lower string) bool {
	for _, scheme := range subscriptionSchemes {
		if strings.HasPrefix(lower, scheme) {
			return true
		}
	}
	return false
}

func ParseURIList(text string) (ParsedSubscription, bool) {
	var nodes []string
	for _, line := range lines(text) {
		line = strings.TrimSpace(line)
		if isSubscriptionScheme(strings.ToLower(line)) && len(utf16Units(line)) > 12 {
			nodes = append(nodes, line)
		}
	}
	if len(nodes) == 0 {
		return ParsedSubscription{}, false
	}
	return ParsedSubscription{len(nodes), strings.Join(nodes, "\n") + "\n"}, true
}

func DecodeSubscriptionBase64(text string) (string, bool) {
	s := strings.Map(func(r rune) rune {
		switch {
		case unicode.IsSpace(r):
			return -1
		case r == '-':
			return '+'
		case r == '_':
			return '/'
		default:
			return r
		}
	}, text)
	s += strings.Repeat("=", (4-len(s)%4)%4)
	data, err := base64.StdEncoding.DecodeString(s)
	if err != nil || strings.ContainsRune(strings.ToValidUTF8(string(data), "\uFFFD"), '\uFFFD') {
		return "", false
	}
	return string(data), true
}

var (
	serverPattern = regexp.MustCompile(`(?:^|[^a-z-])server:[\t\n\v\f\r ]*([^,}\t\n\v\f\r ]+)`)
	hostChars     = regexp.MustCompile(`^[A-Za-z0-9.-]+$`)
)

func ServerHosts(providerContent string) []string {
	hosts := make(map[string]bool)
	add := func(raw string) {
		h := strings.Trim(raw, "\"' []")
		if len(h) <= 253 && hostChars.MatchString(h) {
			hosts[strings.ToLower(h)] = true
		}
	}
	for _, line := range lines(providerContent) {
		t := strings.TrimSpace(line)
		if m := serverPattern.FindStringSubmatch(t); m != nil {
			add(m[1])
			continue
		}
		lower := strings.ToLower(t)
		if strings.HasPrefix(lower, "vmess://") {
			if data, ok := DecodeSubscriptionBase64(t[8:]); ok {
				if addr := parseJSONObject(data)["add"].str(); addr != nil {
					add(*addr)
					continue
				}
			}
		}
		if !isSubscriptionScheme(lower) {
			continue
		}
		start := strings.Index(t, "://") + 3
		if at := strings.LastIndexByte(t, '@'); at >= 0 {
			start = at + 1
		}
		host := t[start:]
		if i := strings.IndexAny(host, ":/?#"); i >= 0 {
			host = host[:i]
		}
		add(host)
	}
	out := make([]string, 0, len(hosts))
	for h := range hosts {
		out = append(out, h)
	}
	sort.Strings(out)
	return out
}

func ProfileName(headers map[string]string) *string {
	lower := make(map[string]string, len(headers))
	for k, v := range headers {
		lower[strings.ToLower(k)] = v
	}
	if title := lower["profile-title"]; title != "" {
		if raw, ok := strings.CutPrefix(title, "base64:"); ok && !strings.ContainsAny(raw, "\r\n") {
			encoding := base64.StdEncoding
			if !strings.Contains(raw, "=") {
				encoding = base64.RawStdEncoding
			}
			if data, err := encoding.DecodeString(raw); err == nil {
				title = strings.ToValidUTF8(string(data), "\uFFFD")
			}
		}
		return &title
	}
	cd := lower["content-disposition"]
	if _, value, ok := strings.Cut(cd, "filename*=UTF-8''"); ok {
		raw, _, _ := strings.Cut(value, ";")
		if name, err := url.QueryUnescape(raw); err == nil {
			name = strings.ToValidUTF8(name, "\uFFFD")
			return &name
		}
		return nil
	}
	if _, value, ok := strings.Cut(cd, "filename="); ok {
		value, _, _ = strings.Cut(value, ";")
		name := strings.Trim(value, "\" ")
		return &name
	}
	return nil
}

type ExitTrace struct {
	IP      string `json:"ip"`
	Country string `json:"country"`
}

func (trace *ExitTrace) UnmarshalJSON(data []byte) error {
	type plain ExitTrace
	var value plain
	if err := decodeWireObject(data, &value, "ip", "country"); err != nil {
		return err
	}
	*trace = ExitTrace(value)
	return nil
}

func ParseCloudflareTrace(text string) *ExitTrace {
	var ip, country *string
	for _, line := range lines(text) {
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		switch k {
		case "ip":
			ip = &v
		case "loc":
			upper := strings.ToUpper(v)
			country = &upper
		}
	}
	if ip == nil || country == nil || len(utf16Units(*country)) != 2 {
		return nil
	}
	return &ExitTrace{*ip, *country}
}

func ParseJSONTrace(text string) *ExitTrace {
	obj := parseJSONObject(text)
	ip := firstString(obj["ip"], obj["query"])
	country := firstString(obj["country"], obj["countryCode"], obj["country_code"])
	if ip == nil || country == nil || len(utf16Units(*country)) != 2 {
		return nil
	}
	for _, unit := range utf16Units(*country) {
		if !unicode.IsLetter(rune(unit)) {
			return nil
		}
	}
	return &ExitTrace{*ip, strings.ToUpper(*country)}
}

func utf16Units(text string) []uint16   { return utf16.Encode([]rune(text)) }
func decodeUTF16(units []uint16) string { return string(utf16.Decode(units)) }
