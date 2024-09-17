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

package vault

import (
	"os"
	"testing"
	"time"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/bank-vaults/secrets-webhook/pkg/common"
)

func TestLoadConfig(t *testing.T) {
	tests := []struct {
		name        string
		annotations map[string]string
		envVars     map[string]string
		configWant  Config
	}{
		{
			name: "Handle deprecated annotations all",
			annotations: map[string]string{
				common.VaultAddrAnnotationDeprecated:                                 "http://vault.example.com",
				common.VaultImageAnnotationDeprecated:                                "vault:latest",
				common.VaultImagePullPolicyAnnotationDeprecated:                      "IfNotPresent",
				common.VaultRoleAnnotationDeprecated:                                 "my-vault-role",
				common.VaultPathAnnotationDeprecated:                                 "secret/data/myapp/config",
				common.VaultSkipVerifyAnnotationDeprecated:                           "true",
				common.VaultTLSSecretAnnotationDeprecated:                            "vault-tls",
				common.VaultIgnoreMissingSecretsAnnotationDeprecated:                 "false",
				common.VaultClientTimeoutAnnotationDeprecated:                        "30s",
				common.VaultTransitKeyIDAnnotationDeprecated:                         "transit-key-id",
				common.VaultTransitPathAnnotationDeprecated:                          "transit/keys/mykey",
				common.VaultAuthMethodAnnotationDeprecated:                           "kubernetes",
				common.VaultTransitBatchSizeAnnotationDeprecated:                     "64",
				common.VaultTokenAuthMountAnnotationDeprecated:                       "token",
				common.VaultServiceaccountAnnotationDeprecated:                       "vault-auth",
				common.VaultNamespaceAnnotationDeprecated:                            "vault-namespace",
				common.VaultServiceAccountTokenVolumeNameAnnotationDeprecated:        "vault-token",
				common.VaultLogLevelAnnotationDeprecated:                             "debug",
				common.VaultEnvPassthroughAnnotationDeprecated:                       "VAULT_SKIP_VERIFY,VAULT_ADDR",
				common.VaultEnvFromPathAnnotationDeprecated:                          "secret/data/myapp/env",
				common.VaultAgentAnnotationDeprecated:                                "true",
				common.VaultAgentConfigmapAnnotationDeprecated:                       "vault-agent-config",
				common.VaultAgentOnceAnnotationDeprecated:                            "false",
				common.VaultAgentShareProcessNamespaceAnnotationDeprecated:           "true",
				common.VaultAgentCPUAnnotationDeprecated:                             "100m",
				common.VaultAgentCPULimitAnnotationDeprecated:                        "100m",
				common.VaultAgentCPURequestAnnotationDeprecated:                      "200m",
				common.VaultAgentMemoryAnnotationDeprecated:                          "128Mi",
				common.VaultAgentMemoryLimitAnnotationDeprecated:                     "128Mi",
				common.VaultAgentMemoryRequestAnnotationDeprecated:                   "258Mi",
				common.VaultConfigfilePathAnnotationDeprecated:                       "/etc/vault/config.json",
				common.VaultAgentEnvVariablesAnnotationDeprecated:                    "VAULT_SKIP_VERIFY=true",
				common.VaultConsulTemplateConfigmapAnnotationDeprecated:              "consul-template-config",
				common.VaultConsulTemplateImageAnnotationDeprecated:                  "consul-template:latest",
				common.VaultConsulTemplateOnceAnnotationDeprecated:                   "false",
				common.VaultConsulTemplatePullPolicyAnnotationDeprecated:             "IfNotPresent",
				common.VaultConsulTemplateShareProcessNamespaceAnnotationDeprecated:  "true",
				common.VaultConsulTemplateCPUAnnotationDeprecated:                    "100m",
				common.VaultConsulTemplateMemoryAnnotationDeprecated:                 "128Mi",
				common.VaultConsulTemplateSecretsMountPathAnnotationDeprecated:       "/etc/vault/config.json",
				common.VaultConsulTemplateInjectInInitcontainersAnnotationDeprecated: "true",
			},
			configWant: Config{
				Addr:                          "http://vault.example.com",
				AgentImage:                    "vault:latest",
				AgentImagePullPolicy:          "IfNotPresent",
				Role:                          "my-vault-role",
				Path:                          "secret/data/myapp/config",
				SkipVerify:                    true,
				TLSSecret:                     "vault-tls",
				IgnoreMissingSecrets:          "false",
				ClientTimeout:                 time.Duration(30) * time.Second,
				TransitKeyID:                  "transit-key-id",
				TransitPath:                   "transit/keys/mykey",
				AuthMethod:                    "kubernetes",
				TransitBatchSize:              64,
				TokenAuthMount:                "token",
				VaultServiceAccount:           "vault-auth",
				VaultNamespace:                "vault-namespace",
				ServiceAccountTokenVolumeName: "vault-token",
				LogLevel:                      "debug",
				Passthrough:                   "VAULT_SKIP_VERIFY,VAULT_ADDR",
				FromPath:                      "secret/data/myapp/env",
				UseAgent:                      true,
				AgentConfigMap:                "vault-agent-config",
				AgentOnce:                     false,
				AgentShareProcess:             true,
				AgentCPURequest:               resource.MustParse("200m"),
				AgentCPULimit:                 resource.MustParse("100m"),
				AgentMemoryRequest:            resource.MustParse("258Mi"),
				AgentMemoryLimit:              resource.MustParse("128Mi"),
				ConfigfilePath:                "/etc/vault/config.json",
				AgentEnvVariables:             "VAULT_SKIP_VERIFY=true",
				CtConfigMap:                   "consul-template-config",
				CtImage:                       "consul-template:latest",
				CtOnce:                        false,
				CtImagePullPolicy:             "IfNotPresent",
				CtShareProcess:                true,
				CtCPU:                         resource.MustParse("100m"),
				CtMemory:                      resource.MustParse("128Mi"),
				CtInjectInInitcontainers:      true,
				CtShareProcessDefault:         "found",
				AgentShareProcessDefault:      "found",
			},
		},
		{
			name: "Handle deprecated annotations mixed",
			annotations: map[string]string{
				common.VaultAddrAnnotationDeprecated:                                 "https://vault.newexample.com",
				common.VaultImageAnnotation:                                          "vault:1.7.0",
				common.VaultImagePullPolicyAnnotationDeprecated:                      "Always",
				common.VaultRoleAnnotationDeprecated:                                 "new-vault-role",
				common.VaultPathAnnotation:                                           "secret/data/newapp/config",
				common.VaultSkipVerifyAnnotation:                                     "false",
				common.VaultTLSSecretAnnotationDeprecated:                            "new-vault-tls",
				common.VaultIgnoreMissingSecretsAnnotation:                           "true",
				common.VaultClientTimeoutAnnotationDeprecated:                        "45s",
				common.VaultTransitKeyIDAnnotation:                                   "new-transit-key-id",
				common.VaultTransitPathAnnotationDeprecated:                          "transit/keys/newkey",
				common.VaultAuthMethodAnnotation:                                     "jwt",
				common.VaultTransitBatchSizeAnnotationDeprecated:                     "32",
				common.VaultTokenAuthMountAnnotation:                                 "new-token",
				common.VaultServiceaccountAnnotationDeprecated:                       "new-vault-auth",
				common.VaultNamespaceAnnotation:                                      "new-vault-namespace",
				common.VaultServiceAccountTokenVolumeNameAnnotationDeprecated:        "new-vault-token",
				common.VaultLogLevelAnnotation:                                       "info",
				common.VaultEnvPassthroughAnnotationDeprecated:                       "VAULT_ADDR,VAULT_NAMESPACE",
				common.VaultEnvFromPathAnnotationDeprecated:                          "secret/data/newapp/env",
				common.VaultAgentAnnotationDeprecated:                                "false",
				common.VaultAgentConfigmapAnnotation:                                 "new-vault-agent-config",
				common.VaultAgentOnceAnnotation:                                      "true",
				common.VaultAgentShareProcessNamespaceAnnotationDeprecated:           "false",
				common.VaultAgentCPUAnnotation:                                       "200m",
				common.VaultAgentCPULimitAnnotationDeprecated:                        "400m",
				common.VaultAgentCPURequestAnnotation:                                "200m",
				common.VaultAgentMemoryAnnotation:                                    "512Mi",
				common.VaultAgentMemoryLimitAnnotationDeprecated:                     "512Mi",
				common.VaultAgentMemoryRequestAnnotation:                             "256Mi",
				common.VaultConfigfilePathAnnotationDeprecated:                       "/etc/new-vault/config.json",
				common.VaultAgentEnvVariablesAnnotation:                              "VAULT_NAMESPACE=new-vault-namespace",
				common.VaultConsulTemplateConfigmapAnnotationDeprecated:              "new-consul-template-config",
				common.VaultConsulTemplateImageAnnotation:                            "consul-template:0.25.0",
				common.VaultConsulTemplateOnceAnnotation:                             "true",
				common.VaultConsulTemplatePullPolicyAnnotationDeprecated:             "Never",
				common.VaultConsulTemplateShareProcessNamespaceAnnotation:            "false",
				common.VaultConsulTemplateCPUAnnotation:                              "150m",
				common.VaultConsulTemplateMemoryAnnotationDeprecated:                 "192Mi",
				common.VaultConsulTemplateSecretsMountPathAnnotation:                 "/etc/new-secrets",
				common.VaultConsulTemplateInjectInInitcontainersAnnotationDeprecated: "false",
			},
			configWant: Config{
				Addr:                          "https://vault.newexample.com",
				AgentImage:                    "vault:1.7.0",
				AgentImagePullPolicy:          "Always",
				Role:                          "new-vault-role",
				Path:                          "secret/data/newapp/config",
				SkipVerify:                    false,
				TLSSecret:                     "new-vault-tls",
				IgnoreMissingSecrets:          "true",
				ClientTimeout:                 time.Duration(45) * time.Second,
				TransitKeyID:                  "new-transit-key-id",
				TransitPath:                   "transit/keys/newkey",
				AuthMethod:                    "jwt",
				TransitBatchSize:              32,
				TokenAuthMount:                "new-token",
				VaultServiceAccount:           "new-vault-auth",
				VaultNamespace:                "new-vault-namespace",
				ServiceAccountTokenVolumeName: "new-vault-token",
				LogLevel:                      "info",
				Passthrough:                   "VAULT_ADDR,VAULT_NAMESPACE",
				FromPath:                      "secret/data/newapp/env",
				UseAgent:                      false,
				AgentConfigMap:                "new-vault-agent-config",
				AgentOnce:                     true,
				AgentShareProcess:             false,
				AgentCPURequest:               resource.MustParse("200m"),
				AgentCPULimit:                 resource.MustParse("200m"),
				AgentMemoryRequest:            resource.MustParse("256Mi"),
				AgentMemoryLimit:              resource.MustParse("512Mi"),
				ConfigfilePath:                "/etc/new-vault/config.json",
				AgentEnvVariables:             "VAULT_NAMESPACE=new-vault-namespace",
				CtConfigMap:                   "new-consul-template-config",
				CtImage:                       "consul-template:0.25.0",
				CtOnce:                        true,
				CtImagePullPolicy:             "Never",
				CtShareProcess:                false,
				CtCPU:                         resource.MustParse("150m"),
				CtMemory:                      resource.MustParse("192Mi"),
				CtInjectInInitcontainers:      false,
				CtShareProcessDefault:         "found",
				AgentShareProcessDefault:      "found",
			},
		},
		{
			name: "Handle deprecated env vars all",
			envVars: map[string]string{
				common.VaultSATokenVolumeNameEnvVarDeprecated: "vault-token",
				common.VaultTransitKeyIDEnvVarDeprecated:      "new-transit-key-id",
				common.VaultTransitPathEnvVarDeprecated:       "transit/keys/newkey",
				common.VaultTransitBatchSizeEnvVarDeprecated:  "32",
				common.VaultNamespaceEnvVarDeprecated:         "new-vault-namespace",
				common.VaultEnvPassthroughEnvVarDeprecated:    "VAULT_SKIP_VERIFY,VAULT_ADDR",
			},
			configWant: Config{
				Addr:                          "https://vault:8200",
				AuthMethod:                    "jwt",
				Role:                          "default",
				Path:                          "kubernetes",
				SkipVerify:                    false,
				TLSSecret:                     "",
				ClientTimeout:                 10 * time.Second,
				UseAgent:                      false,
				CtConfigMap:                   "",
				CtImage:                       "hashicorp/consul-template:0.32.0",
				CtInjectInInitcontainers:      false,
				CtOnce:                        false,
				CtImagePullPolicy:             "IfNotPresent",
				CtShareProcess:                false,
				CtCPU:                         resource.MustParse("100m"),
				CtMemory:                      resource.MustParse("128Mi"),
				ConfigfilePath:                "/vault/secrets",
				AgentConfigMap:                "",
				AgentOnce:                     false,
				AgentShareProcess:             false,
				AgentCPULimit:                 resource.MustParse("100m"),
				AgentMemoryLimit:              resource.MustParse("128Mi"),
				AgentCPURequest:               resource.MustParse("100m"),
				AgentMemoryRequest:            resource.MustParse("128Mi"),
				AgentImage:                    "hashicorp/vault:latest",
				AgentImagePullPolicy:          "IfNotPresent",
				AgentEnvVariables:             "",
				VaultServiceAccount:           "",
				Token:                         "",
				IgnoreMissingSecrets:          "false",
				LogLevel:                      "info",
				ServiceAccountTokenVolumeName: "vault-token",
				TransitKeyID:                  "new-transit-key-id",
				TransitPath:                   "transit/keys/newkey",
				TransitBatchSize:              32,
				VaultNamespace:                "new-vault-namespace",
				CtShareProcessDefault:         "empty",
				AgentShareProcessDefault:      "empty",
				Passthrough:                   "VAULT_SKIP_VERIFY,VAULT_ADDR",
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

			config, err := loadConfig(&metav1.ObjectMeta{Annotations: ttp.annotations})
			assert.NoError(t, err)

			assert.Equal(t, ttp.configWant, config)
		})
	}
}
