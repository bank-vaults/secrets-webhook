// Copyright © 2024 Bank-Vaults Maintainers
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package common

import (
	"os"
	"sync"
	"testing"
	"time"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"k8s.io/apimachinery/pkg/api/resource"
)

func TestLoadSecretInitConfig(t *testing.T) {
	tests := []struct {
		name                 string
		annotations          map[string]string
		envVars              map[string]string
		secretInitConfigWant SecretInitConfig
	}{
		{
			name: "Handle deprecated secret init annotations all",
			annotations: map[string]string{
				VaultEnvDaemonAnnotationDeprecated:          "true",
				VaultEnvDelayAnnotationDeprecated:           "10s",
				VaultEnvEnableJSONLogAnnotationDeprecated:   "true",
				VaultEnvImageAnnotationDeprecated:           "vault:latest",
				VaultEnvImagePullPolicyAnnotationDeprecated: "Always",
			},
			secretInitConfigWant: SecretInitConfig{
				Daemon:          true,
				Delay:           time.Duration(10) * time.Second,
				JSONLog:         "true",
				Image:           "vault:latest",
				ImagePullPolicy: "Always",
				LogLevel:        "info",
				CPURequest:      resource.MustParse("100m"),
				MemoryRequest:   resource.MustParse("128Mi"),
				CPULimit:        resource.MustParse("500m"),
				MemoryLimit:     resource.MustParse("256Mi"),
			},
		},
		{
			name: "Handle deprecated env vars all",
			envVars: map[string]string{
				VaultEnvDaemonEnvVarDeprecated:          "true",
				VaultEnvDelayEnvVarDeprecated:           "10s",
				VaultEnvEnableJSONLogEnvVarDeprecated:   "true",
				VaultEnvImageEnvVarDeprecated:           "ghcr.io/bank-vaults/secret-init:latest",
				VaultEnvLogServerEnvVarDeprecated:       "http://log-server.example.com",
				VaultEnvImagePullPolicyEnvVarDeprecated: "Always",
				VaultEnvCPURequestEnvVarDeprecated:      "50m",
				VaultEnvMemoryRequestEnvVarDeprecated:   "128Mi",
				VaultEnvCPULimitEnvVarDeprecated:        "250m",
				VaultEnvMemoryLimitEnvVarDeprecated:     "512Mi",
			},
			secretInitConfigWant: SecretInitConfig{
				Daemon:          true,
				Delay:           time.Duration(10) * time.Second,
				JSONLog:         "true",
				Image:           "ghcr.io/bank-vaults/secret-init:latest",
				LogServer:       "http://log-server.example.com",
				ImagePullPolicy: "Always",
				LogLevel:        "info",
				CPURequest:      resource.MustParse("50m"),
				MemoryRequest:   resource.MustParse("128Mi"),
				CPULimit:        resource.MustParse("250m"),
				MemoryLimit:     resource.MustParse("512Mi"),
			},
		},
	}

	for _, tt := range tests {
		ttp := tt
		t.Run(ttp.name, func(t *testing.T) {
			for key, value := range ttp.envVars {
				viper.Set(key, value)
			}
			t.Cleanup(func() {
				viper.Reset()
				os.Clearenv()
			})
			SetSecretInitConfigDefaults()

			secretInitConfig := LoadSecretInitConfig(ttp.annotations)
			assert.Equal(t, ttp.secretInitConfigWant, secretInitConfig)
		})
	}
}

// Admission requests load the config concurrently. Run with -race: loading must
// not write to viper, or this reports a data race (and production webhooks crash
// with "concurrent map read and map write").
func TestLoadSecretInitConfigConcurrent(t *testing.T) {
	viper.Set(VaultEnvImageEnvVarDeprecated, "deprecated-image")
	t.Cleanup(func() {
		viper.Reset()
		os.Clearenv()
	})
	SetSecretInitConfigDefaults()

	var wg sync.WaitGroup
	for range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 50 {
				cfg := LoadSecretInitConfig(map[string]string{})
				assert.Equal(t, "deprecated-image", cfg.Image)
			}
		}()
	}
	wg.Wait()
}
