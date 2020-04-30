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
)

// rfc3645 configuration
type rfc3645Config struct {
	// gss-tsig specific fields when using a keytab
	keytabSecret string

	// gss-tsig specific fields when using a username/password
	username   string
	password   string
	krb5Config string
	krb5Realm  string
}

// rfc3645 provider type
type rfc3645Provider struct {
	rfcProvider
	rfc3645Config
}

// NewRfc3645Provider is a factory function for OpenStack rfc3645 providers
func NewRfc3645Provider(host string, port int, zoneName string, keytabSecret string, username string, password string, krb5Config string, axfr bool, domainFilter endpoint.DomainFilter, dryRun bool, minTTL time.Duration, actions rfcActions) (Provider, error) {
	r := &rfc3645Provider{
		rfcProvider{
			host:         host,
			nameserver:   net.JoinHostPort(host, strconv.Itoa(port)),
			zoneName:     dns.Fqdn(zoneName),
			minTTL:       minTTL,
			axfr:         axfr,
			domainFilter: domainFilter,
			dryRun:       dryRun,
		},
		rfc3645Config{
			keytabSecret: keytabSecret,
			username:     username,
			password:     password,
			krb5Config:   krb5Config,
			krb5Realm:    strings.ToUpper(zoneName),
		},
	}
	if actions != nil {
		r.actions = actions
	} else {
		r.actions = r
	}

	log.Infof("Configured RFC3645 with zone '%s' and nameserver '%s'", r.zoneName, r.nameserver)
	return r, nil
}

// KeyName will return TKEY name and TSIG handle to use for followon actions with an a secure connection
func (r rfc3645Provider) KeyData() (keyName *string, handle *gss.GSS, err error) {
	handle, err = gss.New()
	if err != nil {
		return keyName, handle, err
	}

	if r.keytabSecret != "" {
		// TODO: this is unimplemented upstream and will always return an error
		//       the empty string in the function call should eventually be the path to a keytab
		//       as mounted via a secret
		keyName, _, err := handle.NegotiateContextWithKeytab(r.host, r.zoneName, r.username, "")
		return keyName, handle, err
	} else if r.username != "" && r.password != "" {
		keyName, _, err := handle.NegotiateContextWithCredentials(r.host, r.krb5Realm, r.username, r.password)
		return keyName, handle, err
	}
	return keyName, handle, fmt.Errorf("failed to fetch TKEY data")
}

func (r rfc3645Provider) IncomeTransfer(m *dns.Msg, a string) (env chan *dns.Envelope, err error) {
	t := new(dns.Transfer)

	return t.In(m, r.nameserver)
}

func (r rfc3645Provider) SendMessage(msg *dns.Msg) error {
	if r.dryRun {
		log.Debugf("SendMessage.skipped")
		return nil
	}
	log.Debugf("SendMessage")

	keyName, handle, err := r.KeyData()
	if err != nil {
		return err
	}
	defer handle.Close()

	c := gssClient.Client{}
	c.TsigAlgorithm = map[string]*gssClient.TsigAlgorithm{
		tsig.GSS: {
			Generate: handle.GenerateGSS,
			Verify:   handle.VerifyGSS,
		},
	}
	c.TsigSecret = map[string]string{*keyName: ""}
	c.SingleInflight = true

	msg.SetTsig(*keyName, tsig.GSS, 30, time.Now().Unix())

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
