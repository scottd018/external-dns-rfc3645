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

package provider

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/miekg/dns"

	log "github.com/sirupsen/logrus"

	"sigs.k8s.io/external-dns/endpoint"
	"sigs.k8s.io/external-dns/plan"
)

type rfcActions interface {
	SendMessage(msg *dns.Msg) error
	IncomeTransfer(m *dns.Msg, a string) (env chan *dns.Envelope, err error)
}

// rfc provider type
type rfcProvider struct {
	host         string
	nameserver   string
	zoneName     string
	minTTL       time.Duration
	domainFilter endpoint.DomainFilter
	axfr         bool
	dryRun       bool
	actions      rfcActions
}

// clockSkew defines the maximum amount of time that clocks from
// DNS client to DNS server can be off in order for DNS actions to
// succeed
const (
	clockSkew uint16 = 300
)

// Records returns the list of records.
func (r rfcProvider) Records(ctx context.Context) ([]*endpoint.Endpoint, error) {
	rrs, err := r.List()
	if err != nil {
		return nil, err
	}

	var eps []*endpoint.Endpoint

OuterLoop:
	for _, rr := range rrs {
		log.Debugf("Record=%s", rr)

		if rr.Header().Class != dns.ClassINET {
			continue
		}

		rrFqdn := rr.Header().Name
		rrTTL := endpoint.TTL(rr.Header().Ttl)
		var rrType string
		var rrValues []string
		switch rr.Header().Rrtype {
		case dns.TypeCNAME:
			rrValues = []string{rr.(*dns.CNAME).Target}
			rrType = "CNAME"
		case dns.TypeA:
			rrValues = []string{rr.(*dns.A).A.String()}
			rrType = "A"
		case dns.TypeAAAA:
			rrValues = []string{rr.(*dns.AAAA).AAAA.String()}
			rrType = "AAAA"
		case dns.TypeTXT:
			rrValues = (rr.(*dns.TXT).Txt)
			rrType = "TXT"
		default:
			continue // Unhandled record type
		}

		for idx, existingEndpoint := range eps {
			if existingEndpoint.DNSName == strings.TrimSuffix(rrFqdn, ".") && existingEndpoint.RecordType == rrType {
				eps[idx].Targets = append(eps[idx].Targets, rrValues...)
				continue OuterLoop
			}
		}

		ep := endpoint.NewEndpointWithTTL(
			rrFqdn,
			rrType,
			rrTTL,
			rrValues...,
		)

		eps = append(eps, ep)
	}

	return eps, nil
}

func (r rfcProvider) List() ([]dns.RR, error) {
	if !r.axfr {
		log.Debug("axfr is disabled")
		return make([]dns.RR, 0), nil
	}

	log.Debugf("Fetching records for '%s'", r.zoneName)

	m := new(dns.Msg)
	m.SetAxfr(r.zoneName)

	env, err := r.actions.IncomeTransfer(m, r.nameserver)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch records via AXFR: %v", err)
	}

	records := make([]dns.RR, 0)
	for e := range env {
		if e.Error != nil {
			if e.Error == dns.ErrSoa {
				log.Error("AXFR error: unexpected response received from the server")
			} else {
				log.Errorf("AXFR error: %v", e.Error)
			}
			continue
		}
		records = append(records, e.RR...)
	}

	return records, nil
}

// ApplyChanges applies a given set of changes in a given zone.
func (r rfc3645Provider) ApplyChanges(ctx context.Context, changes *plan.Changes) error {
	log.Debugf("ApplyChanges (Create: %d, UpdateOld: %d, UpdateNew: %d, Delete: %d)", len(changes.Create), len(changes.UpdateOld), len(changes.UpdateNew), len(changes.Delete))

	m := new(dns.Msg)
	m.SetUpdate(r.zoneName)

	for _, ep := range changes.Create {

		if !r.domainFilter.Match(ep.DNSName) {
			log.Debugf("Skipping record %s because it was filtered out by the specified --domain-filter", ep.DNSName)
			continue
		}

		r.AddRecord(m, ep)
	}
	for _, ep := range changes.UpdateNew {

		if !r.domainFilter.Match(ep.DNSName) {
			log.Debugf("Skipping record %s because it was filtered out by the specified --domain-filter", ep.DNSName)
			continue
		}

		r.UpdateRecord(m, ep)
	}
	for _, ep := range changes.Delete {

		if !r.domainFilter.Match(ep.DNSName) {
			log.Debugf("Skipping record %s because it was filtered out by the specified --domain-filter", ep.DNSName)
			continue
		}

		r.RemoveRecord(m, ep)
	}

	// only send if there are records available
	if len(m.Ns) > 0 {
		err := r.actions.SendMessage(m)
		if err != nil {
			return fmt.Errorf("RFC3645 update failed: %v", err)
		}
	}

	return nil
}

func (r rfc3645Provider) UpdateRecord(m *dns.Msg, ep *endpoint.Endpoint) error {
	err := r.RemoveRecord(m, ep)
	if err != nil {
		return err
	}

	return r.AddRecord(m, ep)
}

func (r rfc3645Provider) AddRecord(m *dns.Msg, ep *endpoint.Endpoint) error {
	log.Debugf("AddRecord.ep=%s", ep)

	var ttl = int64(r.minTTL.Seconds())
	if ep.RecordTTL.IsConfigured() && int64(ep.RecordTTL) > ttl {
		ttl = int64(ep.RecordTTL)
	}

	for _, target := range ep.Targets {
		newRR := fmt.Sprintf("%s %d %s %s", ep.DNSName, ttl, ep.RecordType, target)
		log.Infof("Adding RR: %s", newRR)

		rr, err := dns.NewRR(newRR)
		if err != nil {
			return fmt.Errorf("failed to build RR: %v", err)
		}

		m.Insert([]dns.RR{rr})
	}

	return nil
}

func (r rfc3645Provider) RemoveRecord(m *dns.Msg, ep *endpoint.Endpoint) error {
	log.Debugf("RemoveRecord.ep=%s", ep)
	for _, target := range ep.Targets {
		newRR := fmt.Sprintf("%s %d %s %s", ep.DNSName, ep.RecordTTL, ep.RecordType, target)
		log.Infof("Removing RR: %s", newRR)

		rr, err := dns.NewRR(newRR)
		if err != nil {
			return fmt.Errorf("failed to build RR: %v", err)
		}

		m.Remove([]dns.RR{rr})
	}

	return nil
}
