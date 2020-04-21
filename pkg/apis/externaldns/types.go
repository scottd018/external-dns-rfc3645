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
	"fmt"
	"reflect"
	"strconv"
	"time"

	"github.com/alecthomas/kingpin"
	"github.com/sirupsen/logrus"
	"sigs.k8s.io/external-dns/source"
)

const (
	passwordMask = "******"
)

var (
	// Version is the current version of the app, generated at build time
	Version = "unknown"
)

// Config is a project-wide configuration
type Config struct {
	Master                         string
	KubeConfig                     string
	RequestTimeout                 time.Duration
	IstioIngressGatewayServices    []string
	ContourLoadBalancerService     string
	SkipperRouteGroupVersion       string
	Sources                        []string
	Namespace                      string
	AnnotationFilter               string
	FQDNTemplate                   string
	CombineFQDNAndAnnotation       bool
	IgnoreHostnameAnnotation       bool
	Compatibility                  string
	PublishInternal                bool
	PublishHostIP                  bool
	AlwaysPublishNotReadyAddresses bool
	ConnectorSourceServer          string
	Provider                       string
	DomainFilter                   []string
	ExcludeDomains                 []string
	ZoneIDFilter                   []string
	InMemoryZones                  []string
	TLSCA                          string
	TLSClientCert                  string
	TLSClientCertKey               string
	Policy                         string
	Registry                       string
	TXTOwnerID                     string
	TXTPrefix                      string
	Interval                       time.Duration
	Once                           bool
	DryRun                         bool
	UpdateEvents                   bool
	LogFormat                      string
	MetricsAddress                 string
	LogLevel                       string
	TXTCacheInterval               time.Duration
	CRDSourceAPIVersion            string
	CRDSourceKind                  string
	ServiceTypeFilter              []string
	CFAPIEndpoint                  string
	CFUsername                     string
	CFPassword                     string
	RFC3645Host                    string
	RFC3645Port                    int
	RFC3645Zone                    string
	RFC3645KeytabSecret            string
	RFC3645AuthUsername            string
	RFC3645AuthPassword            string
	RFC3645AuthKerberosConfig      string
	RFC3645AXFR                    bool
	RFC3645MinTTL                  time.Duration
}

var defaultConfig = &Config{
	Master:                      "",
	KubeConfig:                  "",
	RequestTimeout:              time.Second * 30,
	IstioIngressGatewayServices: []string{"istio-system/istio-ingressgateway"},
	ContourLoadBalancerService:  "heptio-contour/contour",
	SkipperRouteGroupVersion:    "zalando.org/v1",
	Sources:                     nil,
	Namespace:                   "",
	AnnotationFilter:            "",
	FQDNTemplate:                "",
	CombineFQDNAndAnnotation:    false,
	IgnoreHostnameAnnotation:    false,
	Compatibility:               "",
	PublishInternal:             false,
	PublishHostIP:               false,
	ConnectorSourceServer:       "localhost:8080",
	Provider:                    "",
	DomainFilter:                []string{},
	ExcludeDomains:              []string{},
	InMemoryZones:               []string{},
	TLSCA:                       "",
	TLSClientCert:               "",
	TLSClientCertKey:            "",
	Policy:                      "sync",
	Registry:                    "txt",
	TXTOwnerID:                  "default",
	TXTPrefix:                   "",
	TXTCacheInterval:            0,
	Interval:                    time.Minute,
	Once:                        false,
	DryRun:                      false,
	UpdateEvents:                false,
	LogFormat:                   "text",
	MetricsAddress:              ":7979",
	LogLevel:                    logrus.InfoLevel.String(),
	CRDSourceAPIVersion:         "externaldns.k8s.io/v1alpha1",
	CRDSourceKind:               "DNSEndpoint",
	ServiceTypeFilter:           []string{},
	CFAPIEndpoint:               "",
	CFUsername:                  "",
	CFPassword:                  "",
	RFC3645Host:                 "",
	RFC3645Port:                 0,
	RFC3645Zone:                 "",
	RFC3645KeytabSecret:         "",
	RFC3645AuthUsername:         "",
	RFC3645AuthPassword:         "",
	RFC3645AuthKerberosConfig:   "",
	RFC3645AXFR:                 true,
	RFC3645MinTTL:               0,
}

// NewConfig returns new Config object
func NewConfig() *Config {
	return &Config{}
}

func (cfg *Config) String() string {
	// prevent logging of sensitive information
	temp := *cfg

	t := reflect.TypeOf(temp)
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if val, ok := f.Tag.Lookup("secure"); ok && val == "yes" {
			if f.Type.Kind() != reflect.String {
				continue
			}
			v := reflect.ValueOf(&temp).Elem().Field(i)
			if v.String() != "" {
				v.SetString(passwordMask)
			}
		}
	}

	return fmt.Sprintf("%+v", temp)
}

// allLogLevelsAsStrings returns all logrus levels as a list of strings
func allLogLevelsAsStrings() []string {
	var levels []string
	for _, level := range logrus.AllLevels {
		levels = append(levels, level.String())
	}
	return levels
}

// ParseFlags adds and parses flags from command line
func (cfg *Config) ParseFlags(args []string) error {
	app := kingpin.New("external-dns", "ExternalDNS synchronizes exposed Kubernetes Services and Ingresses with DNS providers.\n\nNote that all flags may be replaced with env vars - `--flag` -> `EXTERNAL_DNS_FLAG=1` or `--flag value` -> `EXTERNAL_DNS_FLAG=value`")
	app.Version(Version)
	app.DefaultEnvars()

	// Flags related to Kubernetes
	app.Flag("master", "The Kubernetes API server to connect to (default: auto-detect)").Default(defaultConfig.Master).StringVar(&cfg.Master)
	app.Flag("kubeconfig", "Retrieve target cluster configuration from a Kubernetes configuration file (default: auto-detect)").Default(defaultConfig.KubeConfig).StringVar(&cfg.KubeConfig)
	app.Flag("request-timeout", "Request timeout when calling Kubernetes APIs. 0s means no timeout").Default(defaultConfig.RequestTimeout.String()).DurationVar(&cfg.RequestTimeout)

	// Flags related to cloud foundry
	app.Flag("cf-api-endpoint", "The fully-qualified domain name of the cloud foundry instance you are targeting").Default(defaultConfig.CFAPIEndpoint).StringVar(&cfg.CFAPIEndpoint)
	app.Flag("cf-username", "The username to log into the cloud foundry API").Default(defaultConfig.CFUsername).StringVar(&cfg.CFUsername)
	app.Flag("cf-password", "The password to log into the cloud foundry API").Default(defaultConfig.CFPassword).StringVar(&cfg.CFPassword)

	// Flags related to Contour
	app.Flag("contour-load-balancer", "The fully-qualified name of the Contour load balancer service. (default: heptio-contour/contour)").Default("heptio-contour/contour").StringVar(&cfg.ContourLoadBalancerService)

	// Flags related to Skipper RouteGroup
	app.Flag("skipper-routegroup-groupversion", "The resource version for skipper routegroup").Default(source.DefaultRoutegroupVersion).StringVar(&cfg.SkipperRouteGroupVersion)

	// Flags related to processing sources
	app.Flag("source", "The resource types that are queried for endpoints; specify multiple times for multiple sources (required, options: service, ingress, node, fake, connector, istio-gateway, cloudfoundry, contour-ingressroute, crd, empty, skipper-routegroup)").Required().PlaceHolder("source").EnumsVar(&cfg.Sources, "service", "ingress", "node", "istio-gateway", "cloudfoundry", "contour-ingressroute", "fake", "connector", "crd", "empty", "skipper-routegroup")

	app.Flag("namespace", "Limit sources of endpoints to a specific namespace (default: all namespaces)").Default(defaultConfig.Namespace).StringVar(&cfg.Namespace)
	app.Flag("annotation-filter", "Filter sources managed by external-dns via annotation using label selector semantics (default: all sources)").Default(defaultConfig.AnnotationFilter).StringVar(&cfg.AnnotationFilter)
	app.Flag("fqdn-template", "A templated string that's used to generate DNS names from sources that don't define a hostname themselves, or to add a hostname suffix when paired with the fake source (optional). Accepts comma separated list for multiple global FQDN.").Default(defaultConfig.FQDNTemplate).StringVar(&cfg.FQDNTemplate)
	app.Flag("combine-fqdn-annotation", "Combine FQDN template and Annotations instead of overwriting").BoolVar(&cfg.CombineFQDNAndAnnotation)
	app.Flag("ignore-hostname-annotation", "Ignore hostname annotation when generating DNS names, valid only when using fqdn-template is set (optional, default: false)").BoolVar(&cfg.IgnoreHostnameAnnotation)
	app.Flag("compatibility", "Process annotation semantics from legacy implementations (optional, options: mate, molecule)").Default(defaultConfig.Compatibility).EnumVar(&cfg.Compatibility, "", "mate", "molecule")
	app.Flag("publish-internal-services", "Allow external-dns to publish DNS records for ClusterIP services (optional)").BoolVar(&cfg.PublishInternal)
	app.Flag("publish-host-ip", "Allow external-dns to publish host-ip for headless services (optional)").BoolVar(&cfg.PublishHostIP)
	app.Flag("always-publish-not-ready-addresses", "Always publish also not ready addresses for headless services (optional)").BoolVar(&cfg.AlwaysPublishNotReadyAddresses)
	app.Flag("connector-source-server", "The server to connect for connector source, valid only when using connector source").Default(defaultConfig.ConnectorSourceServer).StringVar(&cfg.ConnectorSourceServer)
	app.Flag("crd-source-apiversion", "API version of the CRD for crd source, e.g. `externaldns.k8s.io/v1alpha1`, valid only when using crd source").Default(defaultConfig.CRDSourceAPIVersion).StringVar(&cfg.CRDSourceAPIVersion)
	app.Flag("crd-source-kind", "Kind of the CRD for the crd source in API group and version specified by crd-source-apiversion").Default(defaultConfig.CRDSourceKind).StringVar(&cfg.CRDSourceKind)
	app.Flag("service-type-filter", "The service types to take care about (default: all, expected: ClusterIP, NodePort, LoadBalancer or ExternalName)").StringsVar(&cfg.ServiceTypeFilter)

	// Flags related to providers
	app.Flag("provider", "The DNS provider where the DNS records will be created (required, options: rfc3645)").Required().PlaceHolder("provider").EnumVar(&cfg.Provider, "rfc3645")
	app.Flag("domain-filter", "Limit possible target zones by a domain suffix; specify multiple times for multiple domains (optional)").Default("").StringsVar(&cfg.DomainFilter)
	app.Flag("exclude-domains", "Exclude subdomains (optional)").Default("").StringsVar(&cfg.ExcludeDomains)

	// Flags related to RFC3645 provider
	app.Flag("rfc3645-host", "When using the RFC3645 provider, specify the host of the DNS server").Default(defaultConfig.RFC3645Host).StringVar(&cfg.RFC3645Host)
	app.Flag("rfc3645-port", "When using the RFC3645 provider, specify the port of the DNS server").Default(strconv.Itoa(defaultConfig.RFC3645Port)).IntVar(&cfg.RFC3645Port)
	app.Flag("rfc3645-zone", "When using the RFC3645 provider, specify the zone entry of the DNS server to use").Default(defaultConfig.RFC3645Zone).StringVar(&cfg.RFC3645Zone)
	app.Flag("rfc3645-keytab-secret", "When using the RFC3645 provider, specify the name of a secret containing the Kerberos keytab used to update records (mutually exclusive with --rfc3645-auth* fields)").Default(defaultConfig.RFC3645KeytabSecret).StringVar(&cfg.RFC3645KeytabSecret)
	app.Flag("rfc3645-auth-username", "When using the RFC3645 provider, specify the username of the user with permissions to update DNS records (requires --rfc3645-auth*; mutually exclusive with --rfc3645-keytab-secret)").Default(defaultConfig.RFC3645AuthUsername).StringVar(&cfg.RFC3645AuthUsername)
	app.Flag("rfc3645-auth-password", "When using the RFC3645 provider, specify the TSIG (base64) value to attached to DNS messages (requires --rfc3645-auth*; mutually exclusive with --rfc3645-keytab-secret)").Default(defaultConfig.RFC3645AuthPassword).StringVar(&cfg.RFC3645AuthPassword)
	app.Flag("rfc3645-auth-kerberos-config", "When using the RFC3645 provider, specify the name of a config map containing the Kerberos config (requires --rfc3645-auth*; mutually exclusive with --rfc3645-keytab-secret)").Default(defaultConfig.RFC3645AuthKerberosConfig).StringVar(&cfg.RFC3645AuthKerberosConfig)
	app.Flag("rfc3645-axfr", "When using the RFC3645 provider, specify either the username and password combination or keytab combination to use for zone transfers (requires one of --rfc3645-auth* or --rfc3645-keytab-secret)").BoolVar(&cfg.RFC3645AXFR)
	app.Flag("rfc3645-min-ttl", "When using the RFC3645 provider, specify minimal TTL (in duration format) for records. This value will be used if the provided TTL for a service/ingress is lower than this").Default(defaultConfig.RFC3645MinTTL.String()).DurationVar(&cfg.RFC3645MinTTL)

	// Flags related to policies
	app.Flag("policy", "Modify how DNS records are synchronized between sources and providers (default: sync, options: sync, upsert-only, create-only)").Default(defaultConfig.Policy).EnumVar(&cfg.Policy, "sync", "upsert-only", "create-only")

	// Flags related to the registry
	app.Flag("registry", "The registry implementation to use to keep track of DNS record ownership (default: txt, options: txt, noop, aws-sd)").Default(defaultConfig.Registry).EnumVar(&cfg.Registry, "txt", "noop", "aws-sd")
	app.Flag("txt-owner-id", "When using the TXT registry, a name that identifies this instance of ExternalDNS (default: default)").Default(defaultConfig.TXTOwnerID).StringVar(&cfg.TXTOwnerID)
	app.Flag("txt-prefix", "When using the TXT registry, a custom string that's prefixed to each ownership DNS record (optional)").Default(defaultConfig.TXTPrefix).StringVar(&cfg.TXTPrefix)

	// Flags related to the main control loop
	app.Flag("txt-cache-interval", "The interval between cache synchronizations in duration format (default: disabled)").Default(defaultConfig.TXTCacheInterval.String()).DurationVar(&cfg.TXTCacheInterval)
	app.Flag("interval", "The interval between two consecutive synchronizations in duration format (default: 1m)").Default(defaultConfig.Interval.String()).DurationVar(&cfg.Interval)
	app.Flag("once", "When enabled, exits the synchronization loop after the first iteration (default: disabled)").BoolVar(&cfg.Once)
	app.Flag("dry-run", "When enabled, prints DNS record changes rather than actually performing them (default: disabled)").BoolVar(&cfg.DryRun)
	app.Flag("events", "When enabled, in addition to running every interval, the reconciliation loop will get triggered when supported sources change (default: disabled)").BoolVar(&cfg.UpdateEvents)

	// Miscellaneous flags
	app.Flag("log-format", "The format in which log messages are printed (default: text, options: text, json)").Default(defaultConfig.LogFormat).EnumVar(&cfg.LogFormat, "text", "json")
	app.Flag("metrics-address", "Specify where to serve the metrics and health check endpoint (default: :7979)").Default(defaultConfig.MetricsAddress).StringVar(&cfg.MetricsAddress)
	app.Flag("log-level", "Set the level of logging. (default: info, options: panic, debug, info, warning, error, fatal").Default(defaultConfig.LogLevel).EnumVar(&cfg.LogLevel, allLogLevelsAsStrings()...)

	_, err := app.Parse(args)
	if err != nil {
		return err
	}

	return nil
}
