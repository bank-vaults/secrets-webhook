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
	"testing"
	"time"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestLoadConfig(t *testing.T) {
	tests := []struct {
		name                 string
		annotations          map[string]string
		envVars              map[string]string
		webhookConfigWant    Config
		secretInitConfigWant SecretInitConfig
	}{
		{
			name: "Handle deprecated annotations all",
			annotations: map[string]string{
				MutateAnnotationDeprecated:                      "false",
				PSPAllowPrivilegeEscalationAnnotationDeprecated: "true",
				RunAsNonRootAnnotationDeprecated:                "true",
				RunAsUserAnnotationDeprecated:                   "1000",
				RunAsGroupAnnotationDeprecated:                  "1000",
				ReadOnlyRootFsAnnotationDeprecated:              "true",
				RegistrySkipVerifyAnnotationDeprecated:          "true",
				MutateProbesAnnotationDeprecated:                "true",
				VaultEnvDaemonAnnotationDeprecated:              "true",
				VaultEnvDelayAnnotationDeprecated:               "10s",
				VaultEnvEnableJSONLogAnnotationDeprecated:       "true",
				VaultEnvImageAnnotationDeprecated:               "vault:latest",
				VaultEnvImagePullPolicyAnnotationDeprecated:     "Always",
			},
			webhookConfigWant: Config{
				Mutate:                      false,
				PspAllowPrivilegeEscalation: true,
				RunAsNonRoot:                true,
				RunAsUser:                   1000,
				RunAsGroup:                  1000,
				ReadOnlyRootFilesystem:      true,
				RegistrySkipVerify:          true,
				MutateProbes:                true,
			},
			secretInitConfigWant: SecretInitConfig{
				Daemon:          true,
				Delay:           time.Duration(10) * time.Second,
				JSONLog:         "true",
				Image:           "vault:latest",
				ImagePullPolicy: "Always",
				CPURequest:      resource.MustParse("50m"),
				MemoryRequest:   resource.MustParse("64Mi"),
				CPULimit:        resource.MustParse("250m"),
				MemoryLimit:     resource.MustParse("64Mi"),
			},
		},
		{
			name: "Handle deprecated annotations mixed",
			annotations: map[string]string{
				MutateAnnotationDeprecated:                      "false",
				PSPAllowPrivilegeEscalationAnnotationDeprecated: "true",
				RunAsGroupAnnotation:                            "1000",
				RegistrySkipVerifyAnnotationDeprecated:          "true",
				MutateProbesAnnotation:                          "true",
			},
			webhookConfigWant: Config{
				Mutate:                      false,
				PspAllowPrivilegeEscalation: true,
				RunAsGroup:                  1000,
				RegistrySkipVerify:          true,
				MutateProbes:                true,
			},
			secretInitConfigWant: SecretInitConfig{
				ImagePullPolicy: "IfNotPresent",
				CPURequest:      resource.MustParse("50m"),
				MemoryRequest:   resource.MustParse("64Mi"),
				CPULimit:        resource.MustParse("250m"),
				MemoryLimit:     resource.MustParse("64Mi"),
			},
		},
		{
			name: "Should stop parsing annotations if mutate is set to skip",
			annotations: map[string]string{
				MutateAnnotationDeprecated:                      "skip",
				PSPAllowPrivilegeEscalationAnnotationDeprecated: "true",
				RunAsGroupAnnotation:                            "1000",
				RegistrySkipVerifyAnnotationDeprecated:          "true",
			},
			webhookConfigWant: Config{
				Mutate: true,
			},
			secretInitConfigWant: SecretInitConfig{
				ImagePullPolicy: "IfNotPresent",
				CPURequest:      resource.MustParse("50m"),
				MemoryRequest:   resource.MustParse("64Mi"),
				CPULimit:        resource.MustParse("250m"),
				MemoryLimit:     resource.MustParse("64Mi"),
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

			whConfig := LoadWebhookConfig(&metav1.ObjectMeta{Annotations: ttp.annotations})
			assert.Equal(t, ttp.webhookConfigWant, whConfig)

			secretInitConfig := LoadSecretInitConfig(&metav1.ObjectMeta{Annotations: ttp.annotations})
			assert.Equal(t, ttp.secretInitConfigWant, secretInitConfig)
		})
	}
}
