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
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/bodgit/tsig"
	gssClient "github.com/bodgit/tsig/client"
	"github.com/bodgit/tsig/gss"
	"github.com/miekg/dns"

	log "github.com/sirupsen/logrus"

	"sigs.k8s.io/external-dns/endpoint"
	"sigs.k8s.io/external-dns/plan"
)

// rfc3645 provider type
type rfc3645Provider struct {
	rawHost    string
	nameserver string
	zoneName   string
	minTTL     time.Duration

	// gss-tsig specific fields when using a keytab
	keytabSecret string

	// gss-tsig specific fields when using a username/password
	username   string
	password   string
	krb5Config string
	krb5Realm  string

	// only consider hosted zones managing domains ending in this suffix
	domainFilter endpoint.DomainFilter
	axfr         bool
	dryRun       bool
	actions      rfc3645Actions
}

type rfc3645Actions interface {
	SendMessage(msg *dns.Msg) error
	IncomeTransfer(m *dns.Msg, a string) (env chan *dns.Envelope, err error)
}

// NewRfc3645Provider is a factory function for OpenStack rfc3645 providers
func NewRfc3645Provider(host string, port int, zoneName string, keytabSecret string, username string, password string, krb5Config string, axfr bool, domainFilter endpoint.DomainFilter, dryRun bool, minTTL time.Duration, actions rfc3645Actions) (Provider, error) {
	r := &rfc3645Provider{
		rawHost:      host,
		nameserver:   net.JoinHostPort(host, strconv.Itoa(port)),
		zoneName:     dns.Fqdn(zoneName),
		keytabSecret: keytabSecret,
		username:     username,
		password:     password,
		krb5Config:   krb5Config,
		krb5Realm:    strings.ToUpper(zoneName),
		minTTL:       minTTL,
		axfr:         axfr,
		domainFilter: domainFilter,
		dryRun:       dryRun,
	}
	if actions != nil {
		r.actions = actions
	} else {
		r.actions = r
	}

	log.Infof("Configured RFC3645 with zone '%s' and nameserver '%s'", r.zoneName, r.nameserver)
	return r, nil
}

// KeyData will return TKEY metadata to use for followon actions with an a secure connection
func (r rfc3645Provider) KeyData(g *gss.GSS) (*string, error) {
	if r.keytabSecret != "" {
		// TODO: this is unimplemented upstream and will always return an error
		//       the empty string in the function call should eventually be the path to a keytab
		//       as mounted via a secret
		keyData, _, err := g.NegotiateContextWithKeytab(r.rawHost, r.zoneName, r.username, "")
		return keyData, err
	} else if r.username != "" && r.password != "" {
		keyData, _, err := g.NegotiateContextWithCredentials(r.rawHost, r.krb5Realm, r.username, r.password)
		return keyData, err
	}
	return nil, fmt.Errorf("failed to fetch TKEY data")
}

// Records returns the list of records.
func (r rfc3645Provider) Records(ctx context.Context) ([]*endpoint.Endpoint, error) {
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

func (r rfc3645Provider) IncomeTransfer(m *dns.Msg, a string) (env chan *dns.Envelope, err error) {
	t := new(dns.Transfer)
	return t.In(m, r.nameserver)
}

func (r rfc3645Provider) List() ([]dns.RR, error) {
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

func (r rfc3645Provider) SendMessage(msg *dns.Msg) error {
	if r.dryRun {
		log.Debugf("SendMessage.skipped")
		return nil
	}
	log.Debugf("SendMessage")

	handle, err := gss.New()
	if err != nil {
		return err
	}
	defer handle.Close()

	keyData, err := r.KeyData(handle)
	if err != nil {
		return err
	}

	c := gssClient.Client{}
	c.TsigAlgorithm = map[string]*gssClient.TsigAlgorithm{
		tsig.GSS: {
			Generate: handle.GenerateGSS,
			Verify:   handle.VerifyGSS,
		},
	}
	c.TsigSecret = map[string]string{*keyData: ""}
	c.SingleInflight = true

	msg.SetTsig(*keyData, tsig.GSS, 30, time.Now().Unix())

	resp, _, err := c.Exchange(msg, r.nameserver)
	if err != nil {
		log.Infof("error in dns.Client.Exchange: %s", err)
		return err
	}
	if resp != nil && resp.Rcode != dns.RcodeSuccess {
		log.Infof("Bad dns.Client.Exchange response: %s", resp)
		return fmt.Errorf("bad return code: %s", dns.RcodeToString[resp.Rcode])
	}

	log.Debugf("SendMessage.success")
	return nil
}
