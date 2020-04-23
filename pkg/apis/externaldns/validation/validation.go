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

package validation

import (
	"errors"
	"fmt"

	"sigs.k8s.io/external-dns/pkg/apis/externaldns"
)

// ValidateConfig performs validation on the Config object
func ValidateConfig(cfg *externaldns.Config) error {
	// TODO: Should probably return field.ErrorList
	if cfg.LogFormat != "text" && cfg.LogFormat != "json" {
		return fmt.Errorf("unsupported log format: %s", cfg.LogFormat)
	}
	if len(cfg.Sources) == 0 {
		return errors.New("no sources specified")
	}
	if cfg.Provider == "" {
		return errors.New("no provider specified")
	}

	if cfg.Provider == "rfc3645" {
		if cfg.RFC3645MinTTL < 0 {
			return errors.New("TTL specified for rfc3645 is negative")
		}

		if cfg.RFC3645AuthPassword == "" && cfg.RFC3645AuthUsername != "" {
			return errors.New("--rfc3645-auth-username provided without specifying --rfc3645-auth-password")
		}

		if cfg.RFC3645AuthPassword != "" && cfg.RFC3645AuthUsername == "" {
			return errors.New("--rfc3645-auth-password provided without specifying --rfc3645-auth-username")
		}
	}

	if cfg.IgnoreHostnameAnnotation && cfg.FQDNTemplate == "" {
		return errors.New("FQDN Template must be set if ignoring annotations")
	}
	return nil
}
