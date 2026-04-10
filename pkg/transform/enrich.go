package transform

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/bilals12/iota/pkg/config"
	"github.com/bilals12/iota/pkg/message"
)

type enrichDNSConfig struct {
	Object config.Object `json:"object"`
}

type enrichDNSReverse struct {
	sourceKey string
	targetKey string
}

func newEnrichDNSReverse(ctx context.Context, cfg config.Config) (*enrichDNSReverse, error) {
	var conf enrichDNSConfig
	if err := config.Decode(cfg.Settings, &conf); err != nil {
		return nil, fmt.Errorf("transform enrich_dns_reverse: %v", err)
	}
	targetKey := conf.Object.TargetKey
	if targetKey == "" {
		targetKey = conf.Object.SourceKey + "_hostname"
	}
	return &enrichDNSReverse{
		sourceKey: conf.Object.SourceKey,
		targetKey: targetKey,
	}, nil
}

func (t *enrichDNSReverse) Transform(ctx context.Context, msg *message.Message) ([]*message.Message, error) {
	if msg.IsControl() {
		return []*message.Message{msg}, nil
	}
	v := msg.GetValue(t.sourceKey)
	if !v.Exists() {
		return []*message.Message{msg}, nil
	}

	ip := v.String()
	names, err := net.LookupAddr(ip)
	if err != nil || len(names) == 0 {
		return []*message.Message{msg}, nil
	}

	hostname := strings.TrimSuffix(names[0], ".")
	if err := msg.SetValue(t.targetKey, hostname); err != nil {
		return nil, fmt.Errorf("transform enrich_dns_reverse: %v", err)
	}
	return []*message.Message{msg}, nil
}

type enrichDNSForward struct {
	sourceKey string
	targetKey string
}

func newEnrichDNSForward(ctx context.Context, cfg config.Config) (*enrichDNSForward, error) {
	var conf enrichDNSConfig
	if err := config.Decode(cfg.Settings, &conf); err != nil {
		return nil, fmt.Errorf("transform enrich_dns_forward: %v", err)
	}
	targetKey := conf.Object.TargetKey
	if targetKey == "" {
		targetKey = conf.Object.SourceKey + "_ips"
	}
	return &enrichDNSForward{
		sourceKey: conf.Object.SourceKey,
		targetKey: targetKey,
	}, nil
}

func (t *enrichDNSForward) Transform(ctx context.Context, msg *message.Message) ([]*message.Message, error) {
	if msg.IsControl() {
		return []*message.Message{msg}, nil
	}
	v := msg.GetValue(t.sourceKey)
	if !v.Exists() {
		return []*message.Message{msg}, nil
	}

	hostname := v.String()
	ips, err := net.LookupIP(hostname)
	if err != nil || len(ips) == 0 {
		return []*message.Message{msg}, nil
	}

	ipStrs := make([]string, len(ips))
	for i, ip := range ips {
		ipStrs[i] = ip.String()
	}

	if err := msg.SetValue(t.targetKey, ipStrs); err != nil {
		return nil, fmt.Errorf("transform enrich_dns_forward: %v", err)
	}
	return []*message.Message{msg}, nil
}

type enrichHTTPGetConfig struct {
	Object  config.Object     `json:"object"`
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers"`
	Timeout string            `json:"timeout"`
}

type enrichHTTPGet struct {
	sourceKey string
	targetKey string
	urlTmpl   string
	headers   map[string]string
	client    *http.Client
}

func newEnrichHTTPGet(ctx context.Context, cfg config.Config) (*enrichHTTPGet, error) {
	var conf enrichHTTPGetConfig
	if err := config.Decode(cfg.Settings, &conf); err != nil {
		return nil, fmt.Errorf("transform enrich_http_get: %v", err)
	}

	timeout := 10 * time.Second
	if conf.Timeout != "" {
		d, err := time.ParseDuration(conf.Timeout)
		if err == nil {
			timeout = d
		}
	}

	targetKey := conf.Object.TargetKey
	if targetKey == "" {
		targetKey = "enrichment"
	}

	return &enrichHTTPGet{
		sourceKey: conf.Object.SourceKey,
		targetKey: targetKey,
		urlTmpl:   conf.URL,
		headers:   conf.Headers,
		client:    &http.Client{Timeout: timeout},
	}, nil
}

func (t *enrichHTTPGet) Transform(ctx context.Context, msg *message.Message) ([]*message.Message, error) {
	if msg.IsControl() {
		return []*message.Message{msg}, nil
	}

	url := t.urlTmpl
	if t.sourceKey != "" {
		v := msg.GetValue(t.sourceKey)
		if v.Exists() {
			url = strings.ReplaceAll(url, "{value}", v.String())
		}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return []*message.Message{msg}, nil
	}

	for k, v := range t.headers {
		req.Header.Set(k, v)
	}

	resp, err := t.client.Do(req)
	if err != nil {
		return []*message.Message{msg}, nil
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return []*message.Message{msg}, nil
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return []*message.Message{msg}, nil
	}

	if json.Valid(body) {
		if err := msg.SetValue(t.targetKey, json.RawMessage(body)); err != nil {
			return nil, fmt.Errorf("transform enrich_http_get: %v", err)
		}
	} else {
		if err := msg.SetValue(t.targetKey, string(body)); err != nil {
			return nil, fmt.Errorf("transform enrich_http_get: %v", err)
		}
	}

	return []*message.Message{msg}, nil
}

type enrichGeoIPConfig struct {
	Object config.Object `json:"object"`
}

type enrichGeoIP struct {
	sourceKey string
	targetKey string
}

func newEnrichGeoIP(ctx context.Context, cfg config.Config) (*enrichGeoIP, error) {
	var conf enrichGeoIPConfig
	if err := config.Decode(cfg.Settings, &conf); err != nil {
		return nil, fmt.Errorf("transform enrich_geoip: %v", err)
	}
	targetKey := conf.Object.TargetKey
	if targetKey == "" {
		targetKey = conf.Object.SourceKey + "_geo"
	}
	return &enrichGeoIP{
		sourceKey: conf.Object.SourceKey,
		targetKey: targetKey,
	}, nil
}

func (t *enrichGeoIP) Transform(ctx context.Context, msg *message.Message) ([]*message.Message, error) {
	if msg.IsControl() {
		return []*message.Message{msg}, nil
	}

	v := msg.GetValue(t.sourceKey)
	if !v.Exists() {
		return []*message.Message{msg}, nil
	}

	ip := net.ParseIP(v.String())
	if ip == nil {
		return []*message.Message{msg}, nil
	}

	geo := map[string]interface{}{
		"is_private":  isPrivateIP(ip),
		"is_loopback": ip.IsLoopback(),
		"is_global":   ip.IsGlobalUnicast() && !isPrivateIP(ip),
	}

	if err := msg.SetValue(t.targetKey, geo); err != nil {
		return nil, fmt.Errorf("transform enrich_geoip: %v", err)
	}
	return []*message.Message{msg}, nil
}

func isPrivateIP(ip net.IP) bool {
	if ip4 := ip.To4(); ip4 != nil {
		return ip4[0] == 10 ||
			(ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31) ||
			(ip4[0] == 192 && ip4[1] == 168)
	}
	return false
}

func init() {
	// Register additional transform types
}
