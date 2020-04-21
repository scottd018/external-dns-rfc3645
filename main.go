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

package main

import (
	"context"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	log "github.com/sirupsen/logrus"

	_ "k8s.io/client-go/plugin/pkg/client/auth"

	"sigs.k8s.io/external-dns/controller"
	"sigs.k8s.io/external-dns/endpoint"
	"sigs.k8s.io/external-dns/pkg/apis/externaldns"
	"sigs.k8s.io/external-dns/pkg/apis/externaldns/validation"
	"sigs.k8s.io/external-dns/plan"
	"sigs.k8s.io/external-dns/provider"
	"sigs.k8s.io/external-dns/registry"
	"sigs.k8s.io/external-dns/source"
)

func main() {
	cfg := externaldns.NewConfig()
	if err := cfg.ParseFlags(os.Args[1:]); err != nil {
		log.Fatalf("flag parsing error: %v", err)
	}
	log.Infof("config: %s", cfg)

	if err := validation.ValidateConfig(cfg); err != nil {
		log.Fatalf("config validation failed: %v", err)
	}

	if cfg.LogFormat == "json" {
		log.SetFormatter(&log.JSONFormatter{})
	}
	if cfg.DryRun {
		log.Info("running in dry-run mode. No changes to DNS records will be made.")
	}

	ll, err := log.ParseLevel(cfg.LogLevel)
	if err != nil {
		log.Fatalf("failed to parse log level: %v", err)
	}
	log.SetLevel(ll)

	ctx := context.Background()

	stopChan := make(chan struct{}, 1)

	go serveMetrics(cfg.MetricsAddress)
	go handleSigterm(stopChan)

	// Create a source.Config from the flags passed by the user.
	sourceCfg := &source.Config{
		Namespace:                      cfg.Namespace,
		AnnotationFilter:               cfg.AnnotationFilter,
		FQDNTemplate:                   cfg.FQDNTemplate,
		CombineFQDNAndAnnotation:       cfg.CombineFQDNAndAnnotation,
		IgnoreHostnameAnnotation:       cfg.IgnoreHostnameAnnotation,
		Compatibility:                  cfg.Compatibility,
		PublishInternal:                cfg.PublishInternal,
		PublishHostIP:                  cfg.PublishHostIP,
		AlwaysPublishNotReadyAddresses: cfg.AlwaysPublishNotReadyAddresses,
		ConnectorServer:                cfg.ConnectorSourceServer,
		CRDSourceAPIVersion:            cfg.CRDSourceAPIVersion,
		CRDSourceKind:                  cfg.CRDSourceKind,
		KubeConfig:                     cfg.KubeConfig,
		KubeMaster:                     cfg.Master,
		ServiceTypeFilter:              cfg.ServiceTypeFilter,
		IstioIngressGatewayServices:    cfg.IstioIngressGatewayServices,
		CFAPIEndpoint:                  cfg.CFAPIEndpoint,
		CFUsername:                     cfg.CFUsername,
		CFPassword:                     cfg.CFPassword,
		ContourLoadBalancerService:     cfg.ContourLoadBalancerService,
		SkipperRouteGroupVersion:       cfg.SkipperRouteGroupVersion,
		RequestTimeout:                 cfg.RequestTimeout,
	}

	// Lookup all the selected sources by names and pass them the desired configuration.
	sources, err := source.ByNames(&source.SingletonClientGenerator{
		KubeConfig: cfg.KubeConfig,
		KubeMaster: cfg.Master,
		// If update events are enabled, disable timeout.
		RequestTimeout: func() time.Duration {
			if cfg.UpdateEvents {
				return 0
			}
			return cfg.RequestTimeout
		}(),
	}, cfg.Sources, sourceCfg)
	if err != nil {
		log.Fatal(err)
	}

	// Combine multiple sources into a single, deduplicated source.
	endpointsSource := source.NewDedupSource(source.NewMultiSource(sources))

	domainFilter := endpoint.NewDomainFilterWithExclusions(cfg.DomainFilter, cfg.ExcludeDomains)

	var p provider.Provider
	switch cfg.Provider {
	case "rfc3645":
		p, err = provider.NewRfc3645Provider(cfg.RFC3645Host, cfg.RFC3645Port, cfg.RFC3645Zone, cfg.RFC3645KeytabSecret, cfg.RFC3645AuthUsername, cfg.RFC3645AuthPassword, cfg.RFC3645AuthKerberosConfig, cfg.RFC3645AXFR, domainFilter, cfg.DryRun, cfg.RFC3645MinTTL, nil)
	default:
		log.Fatalf("unknown dns provider: %s", cfg.Provider)
	}
	if err != nil {
		log.Fatal(err)
	}

	var r registry.Registry
	switch cfg.Registry {
	case "noop":
		r, err = registry.NewNoopRegistry(p)
	case "txt":
		r, err = registry.NewTXTRegistry(p, cfg.TXTPrefix, cfg.TXTOwnerID, cfg.TXTCacheInterval)
	default:
		log.Fatalf("unknown registry: %s", cfg.Registry)
	}

	if err != nil {
		log.Fatal(err)
	}

	policy, exists := plan.Policies[cfg.Policy]
	if !exists {
		log.Fatalf("unknown policy: %s", cfg.Policy)
	}

	ctrl := controller.Controller{
		Source:       endpointsSource,
		Registry:     r,
		Policy:       policy,
		Interval:     cfg.Interval,
		DomainFilter: domainFilter,
	}

	if cfg.UpdateEvents {
		// Add RunOnce as the handler function that will be called when ingress/service sources have changed.
		// Note that k8s Informers will perform an initial list operation, which results in the handler
		// function initially being called for every Service/Ingress that exists limted by minInterval.
		ctrl.Source.AddEventHandler(func() error { return ctrl.RunOnce(ctx) }, stopChan, 1*time.Minute)
	}

	if cfg.Once {
		err := ctrl.RunOnce(ctx)
		if err != nil {
			log.Fatal(err)
		}

		os.Exit(0)
	}
	ctrl.Run(ctx, stopChan)
}

func handleSigterm(stopChan chan struct{}) {
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGTERM)
	<-signals
	log.Info("Received SIGTERM. Terminating...")
	close(stopChan)
}

func serveMetrics(address string) {
	http.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	http.Handle("/metrics", promhttp.Handler())

	log.Fatal(http.ListenAndServe(address, nil))
}
