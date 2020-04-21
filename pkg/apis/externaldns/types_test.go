/*
Copyright 2017 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package externaldns

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	minimalConfig = &Config{
		Master:                     "",
		KubeConfig:                 "",
		RequestTimeout:             time.Second * 30,
		ContourLoadBalancerService: "heptio-contour/contour",
		SkipperRouteGroupVersion:   "zalando.org/v1",
		Sources:                    []string{"service"},
		Namespace:                  "",
		FQDNTemplate:               "",
		Compatibility:              "",
		Provider:                   "google",
		DomainFilter:               []string{""},
		ExcludeDomains:             []string{""},
		ZoneIDFilter:               []string{""},
		InMemoryZones:              []string{""},
		Policy:                     "sync",
		Registry:                   "txt",
		TXTOwnerID:                 "default",
		TXTPrefix:                  "",
		TXTCacheInterval:           0,
		Interval:                   time.Minute,
		Once:                       false,
		DryRun:                     false,
		UpdateEvents:               false,
		LogFormat:                  "text",
		MetricsAddress:             ":7979",
		LogLevel:                   logrus.InfoLevel.String(),
		ConnectorSourceServer:      "localhost:8080",
		CRDSourceAPIVersion:        "externaldns.k8s.io/v1alpha1",
		CRDSourceKind:              "DNSEndpoint",
	}

	overriddenConfig = &Config{
		Master:                     "http://127.0.0.1:8080",
		KubeConfig:                 "/some/path",
		RequestTimeout:             time.Second * 77,
		ContourLoadBalancerService: "heptio-contour-other/contour-other",
		SkipperRouteGroupVersion:   "zalando.org/v2",
		Sources:                    []string{"service", "ingress", "connector"},
		Namespace:                  "namespace",
		IgnoreHostnameAnnotation:   true,
		FQDNTemplate:               "{{.Name}}.service.example.com",
		Compatibility:              "mate",
		Provider:                   "google",
		DomainFilter:               []string{"example.org", "company.com"},
		ExcludeDomains:             []string{"xapi.example.org", "xapi.company.com"},
		ZoneIDFilter:               []string{"/hostedzone/ZTST1", "/hostedzone/ZTST2"},
		InMemoryZones:              []string{"example.org", "company.com"},
		TLSCA:                      "/path/to/ca.crt",
		TLSClientCert:              "/path/to/cert.pem",
		TLSClientCertKey:           "/path/to/key.pem",
		Policy:                     "upsert-only",
		Registry:                   "noop",
		TXTOwnerID:                 "owner-1",
		TXTPrefix:                  "associated-txt-record",
		TXTCacheInterval:           12 * time.Hour,
		Interval:                   10 * time.Minute,
		Once:                       true,
		DryRun:                     true,
		UpdateEvents:               true,
		LogFormat:                  "json",
		MetricsAddress:             "127.0.0.1:9099",
		LogLevel:                   logrus.DebugLevel.String(),
		ConnectorSourceServer:      "localhost:8081",
		CRDSourceAPIVersion:        "test.k8s.io/v1alpha1",
		CRDSourceKind:              "Endpoint",
	}
)

func TestParseFlags(t *testing.T) {
	for _, ti := range []struct {
		title    string
		args     []string
		envVars  map[string]string
		expected *Config
	}{
		{
			title: "default config with minimal flags defined",
			args: []string{
				"--source=service",
				"--provider=rfc3645",
			},
			envVars:  map[string]string{},
			expected: minimalConfig,
		},
		{
			title: "override everything via flags",
			args: []string{
				"--master=http://127.0.0.1:8080",
				"--kubeconfig=/some/path",
				"--request-timeout=77s",
				"--contour-load-balancer=heptio-contour-other/contour-other",
				"--skipper-routegroup-groupversion=zalando.org/v2",
				"--source=service",
				"--source=ingress",
				"--source=connector",
				"--namespace=namespace",
				"--fqdn-template={{.Name}}.service.example.com",
				"--ignore-hostname-annotation",
				"--compatibility=mate",
				"--inmemory-zone=example.org",
				"--inmemory-zone=company.com",
				"--tls-ca=/path/to/ca.crt",
				"--tls-client-cert=/path/to/cert.pem",
				"--tls-client-cert-key=/path/to/key.pem",
				"--domain-filter=example.org",
				"--domain-filter=company.com",
				"--exclude-domains=xapi.example.org",
				"--exclude-domains=xapi.company.com",
				"--zone-id-filter=/hostedzone/ZTST1",
				"--zone-id-filter=/hostedzone/ZTST2",
				"--policy=upsert-only",
				"--registry=noop",
				"--txt-owner-id=owner-1",
				"--txt-prefix=associated-txt-record",
				"--txt-cache-interval=12h",
				"--interval=10m",
				"--once",
				"--dry-run",
				"--events",
				"--log-format=json",
				"--metrics-address=127.0.0.1:9099",
				"--log-level=debug",
				"--connector-source-server=localhost:8081",
				"--crd-source-apiversion=test.k8s.io/v1alpha1",
				"--crd-source-kind=Endpoint",
			},
			envVars:  map[string]string{},
			expected: overriddenConfig,
		},
		{
			title: "override everything via environment variables",
			args:  []string{},
			envVars: map[string]string{
				"EXTERNAL_DNS_MASTER":                          "http://127.0.0.1:8080",
				"EXTERNAL_DNS_KUBECONFIG":                      "/some/path",
				"EXTERNAL_DNS_REQUEST_TIMEOUT":                 "77s",
				"EXTERNAL_DNS_CONTOUR_LOAD_BALANCER":           "heptio-contour-other/contour-other",
				"EXTERNAL_DNS_SKIPPER_ROUTEGROUP_GROUPVERSION": "zalando.org/v2",
				"EXTERNAL_DNS_SOURCE":                          "service\ningress\nconnector",
				"EXTERNAL_DNS_NAMESPACE":                       "namespace",
				"EXTERNAL_DNS_FQDN_TEMPLATE":                   "{{.Name}}.service.example.com",
				"EXTERNAL_DNS_IGNORE_HOSTNAME_ANNOTATION":      "1",
				"EXTERNAL_DNS_COMPATIBILITY":                   "mate",
				"EXTERNAL_DNS_PROVIDER":                        "google",
				"EXTERNAL_DNS_CLOUDFLARE_PROXIED":              "1",
				"EXTERNAL_DNS_CLOUDFLARE_ZONES_PER_PAGE":       "20",
				"EXTERNAL_DNS_INMEMORY_ZONE":                   "example.org\ncompany.com",
				"EXTERNAL_DNS_DOMAIN_FILTER":                   "example.org\ncompany.com",
				"EXTERNAL_DNS_EXCLUDE_DOMAINS":                 "xapi.example.org\nxapi.company.com",
				"EXTERNAL_DNS_TLS_CA":                          "/path/to/ca.crt",
				"EXTERNAL_DNS_TLS_CLIENT_CERT":                 "/path/to/cert.pem",
				"EXTERNAL_DNS_TLS_CLIENT_CERT_KEY":             "/path/to/key.pem",
				"EXTERNAL_DNS_POLICY":                          "upsert-only",
				"EXTERNAL_DNS_REGISTRY":                        "noop",
				"EXTERNAL_DNS_TXT_OWNER_ID":                    "owner-1",
				"EXTERNAL_DNS_TXT_PREFIX":                      "associated-txt-record",
				"EXTERNAL_DNS_TXT_CACHE_INTERVAL":              "12h",
				"EXTERNAL_DNS_INTERVAL":                        "10m",
				"EXTERNAL_DNS_ONCE":                            "1",
				"EXTERNAL_DNS_DRY_RUN":                         "1",
				"EXTERNAL_DNS_EVENTS":                          "1",
				"EXTERNAL_DNS_LOG_FORMAT":                      "json",
				"EXTERNAL_DNS_METRICS_ADDRESS":                 "127.0.0.1:9099",
				"EXTERNAL_DNS_LOG_LEVEL":                       "debug",
				"EXTERNAL_DNS_CONNECTOR_SOURCE_SERVER":         "localhost:8081",
				"EXTERNAL_DNS_CRD_SOURCE_APIVERSION":           "test.k8s.io/v1alpha1",
				"EXTERNAL_DNS_CRD_SOURCE_KIND":                 "Endpoint",
			},
			expected: overriddenConfig,
		},
	} {
		t.Run(ti.title, func(t *testing.T) {
			originalEnv := setEnv(t, ti.envVars)
			defer func() { restoreEnv(t, originalEnv) }()

			cfg := NewConfig()
			require.NoError(t, cfg.ParseFlags(ti.args))
			assert.Equal(t, ti.expected, cfg)
		})
	}
}

// helper functions

func setEnv(t *testing.T, env map[string]string) map[string]string {
	originalEnv := map[string]string{}

	for k, v := range env {
		originalEnv[k] = os.Getenv(k)
		require.NoError(t, os.Setenv(k, v))
	}

	return originalEnv
}

func restoreEnv(t *testing.T, originalEnv map[string]string) {
	for k, v := range originalEnv {
		require.NoError(t, os.Setenv(k, v))
	}
}

func TestPasswordsNotLogged(t *testing.T) {
	cfg := Config{
		RFC3645AuthPassword: "rfc3645-pass",
	}

	s := cfg.String()

	assert.False(t, strings.Contains(s, "rfc3645-pass"))
}
