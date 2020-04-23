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
	"testing"

	"sigs.k8s.io/external-dns/pkg/apis/externaldns"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	invalidRfc3645Configs = []*externaldns.Config{
		{
			LogFormat:           "json",
			Sources:             []string{"test-source"},
			Provider:            "rfc3645",
			RFC3645AuthUsername: "test-user",
			RFC3645AuthPassword: "",
			RFC3645MinTTL:       3600,
		},
		{
			LogFormat:           "json",
			Sources:             []string{"test-source"},
			Provider:            "rfc3645",
			RFC3645AuthUsername: "",
			RFC3645AuthPassword: "test-pass",
			RFC3645MinTTL:       3600,
		},
		{
			LogFormat:           "json",
			Sources:             []string{"test-source"},
			Provider:            "rfc3645",
			RFC3645AuthUsername: "test-user",
			RFC3645AuthPassword: "test-pass",
			RFC3645MinTTL:       -1,
		},
	}
	validRfc3645Configs = []*externaldns.Config{
		{
			LogFormat:           "json",
			Sources:             []string{"test-source"},
			Provider:            "rfc3645",
			RFC3645AuthUsername: "test-user",
			RFC3645AuthPassword: "test-pass",
			RFC3645MinTTL:       3600,
		},
	}
)

func TestValidateFlags(t *testing.T) {
	cfg := newValidConfig(t)
	assert.NoError(t, ValidateConfig(cfg))

	cfg = newValidConfig(t)
	cfg.LogFormat = "test"
	assert.Error(t, ValidateConfig(cfg))

	cfg = newValidConfig(t)
	cfg.LogFormat = ""
	assert.Error(t, ValidateConfig(cfg))

	for _, format := range []string{"text", "json"} {
		cfg = newValidConfig(t)
		cfg.LogFormat = format
		assert.NoError(t, ValidateConfig(cfg))
	}

	cfg = newValidConfig(t)
	cfg.Sources = []string{}
	assert.Error(t, ValidateConfig(cfg))

	cfg = newValidConfig(t)
	cfg.Provider = ""
	assert.Error(t, ValidateConfig(cfg))
}

func newValidConfig(t *testing.T) *externaldns.Config {
	cfg := externaldns.NewConfig()

	cfg.LogFormat = "json"
	cfg.Sources = []string{"test-source"}
	cfg.Provider = "test-provider"

	require.NoError(t, ValidateConfig(cfg))

	return cfg
}

func TestValidateBadIgnoreHostnameAnnotationsConfig(t *testing.T) {
	cfg := externaldns.NewConfig()
	cfg.IgnoreHostnameAnnotation = true
	cfg.FQDNTemplate = ""

	assert.Error(t, ValidateConfig(cfg))
}

func TestValidateBadRfc3645Config(t *testing.T) {
	for _, cfg := range invalidRfc3645Configs {
		err := ValidateConfig(cfg)

		assert.NotNil(t, err)
	}
}

func TestValidateGoodRfc3645Config(t *testing.T) {
	for _, cfg := range validRfc3645Configs {
		err := ValidateConfig(cfg)

		assert.Nil(t, err)
	}
}
