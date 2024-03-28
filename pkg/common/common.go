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
	"strings"

	corev1 "k8s.io/api/core/v1"
)

const (
	// Webhook annotations
	// ref: https://bank-vaults.dev/docs/mutating-webhook/annotations/
	PSPAllowPrivilegeEscalationAnnotation = "secrets-webhook.security.banzaicloud.io/psp-allow-privilege-escalation"
	RunAsNonRootAnnotation                = "secrets-webhook.security.banzaicloud.io/run-as-non-root"
	RunAsUserAnnotation                   = "secrets-webhook.security.banzaicloud.io/run-as-user"
	RunAsGroupAnnotation                  = "secrets-webhook.security.banzaicloud.io/run-as-group"
	ReadOnlyRootFsAnnotation              = "secrets-webhook.security.banzaicloud.io/readonly-root-fs"
	RegistrySkipVerifyAnnotation          = "secrets-webhook.security.banzaicloud.io/registry-skip-verify"
	MutateAnnotation                      = "secrets-webhook.security.banzaicloud.io/mutate"
	MutateProbesAnnotation                = "secrets-webhook.security.banzaicloud.io/mutate-probes"
	ProviderAnnotation                    = "secrets-webhook.security.banzaicloud.io/provider"

	// Secret-init annotations
	SecretInitDaemonAnnotation          = "secrets-webhook.security.banzaicloud.io/secret-init-daemon"
	SecretInitDelayAnnotation           = "secrets-webhook.security.banzaicloud.io/secret-init-delay"
	SecretInitJSONLogAnnotation         = "secrets-webhook.security.banzaicloud.io/secret-init-json-log"
	SecretInitImageAnnotation           = "secrets-webhook.security.banzaicloud.io/secret-init-image"
	SecretInitImagePullPolicyAnnotation = "secrets-webhook.security.banzaicloud.io/secret-init-image-pull-policy"

	// Vault annotations
	VaultAddrAnnotation                     = "vault.security.banzaicloud.io/vault-addr"
	VaultImageAnnotation                    = "vault.security.banzaicloud.io/vault-image"
	VaultImagePullPolicyAnnotation          = "vault.security.banzaicloud.io/vault-image-pull-policy"
	VaultRoleAnnotation                     = "vault.security.banzaicloud.io/vault-role"
	VaultPathAnnotation                     = "vault.security.banzaicloud.io/vault-path"
	VaultSkipVerifyAnnotation               = "vault.security.banzaicloud.io/vault-skip-verify"
	VaultTLSSecretAnnotation                = "vault.security.banzaicloud.io/vault-tls-secret"
	VaultIgnoreMissingSecretsAnnotation     = "vault.security.banzaicloud.io/vault-ignore-missing-secrets"
	VaultClientTimeoutAnnotation            = "vault.security.banzaicloud.io/vault-client-timeout"
	TransitKeyIDAnnotation                  = "vault.security.banzaicloud.io/transit-key-id"
	TransitPathAnnotation                   = "vault.security.banzaicloud.io/transit-path"
	VaultAuthMethodAnnotation               = "vault.security.banzaicloud.io/vault-auth-method"
	TransitBatchSizeAnnotation              = "vault.security.banzaicloud.io/transit-batch-size"
	TokenAuthMountAnnotation                = "vault.security.banzaicloud.io/token-auth-mount"
	VaultServiceaccountAnnotation           = "vault.security.banzaicloud.io/vault-serviceaccount"
	VaultNamespaceAnnotation                = "vault.security.banzaicloud.io/vault-namespace"
	ServiceAccountTokenVolumeNameAnnotation = "vault.security.banzaicloud.io/service-account-token-volume-name"
	LogLevelAnnotation                      = "vault.security.banzaicloud.io/log-level"
	VaultPassthroughAnnotation              = "vault.security.banzaicloud.io/vault-passthrough"
	VaultFromPathAnnotation                 = "vault.security.banzaicloud.io/vault-from-path"

	// Vault agent annotations
	// ref: https://bank-vaults.dev/docs/mutating-webhook/vault-agent-templating/
	VaultAgentAnnotation                      = "vault.security.banzaicloud.io/vault-agent"
	VaultAgentConfigmapAnnotation             = "vault.security.banzaicloud.io/vault-agent-configmap"
	VaultAgentOnceAnnotation                  = "vault.security.banzaicloud.io/vault-agent-once"
	VaultAgentShareProcessNamespaceAnnotation = "vault.security.banzaicloud.io/vault-agent-share-process-namespace"
	VaultAgentCPUAnnotation                   = "vault.security.banzaicloud.io/vault-agent-cpu"
	VaultAgentCPULimitAnnotation              = "vault.security.banzaicloud.io/vault-agent-cpu-limit"
	VaultAgentCPURequestAnnotation            = "vault.security.banzaicloud.io/vault-agent-cpu-request"
	VaultAgentMemoryAnnotation                = "vault.security.banzaicloud.io/vault-agent-memory"
	VaultAgentMemoryLimitAnnotation           = "vault.security.banzaicloud.io/vault-agent-memory-limit"
	VaultAgentMemoryRequestAnnotation         = "vault.security.banzaicloud.io/vault-agent-memory-request"
	VaultConfigfilePathAnnotation             = "vault.security.banzaicloud.io/vault-configfile-path"
	VaultAgentEnvVariablesAnnotation          = "vault.security.banzaicloud.io/vault-agent-env-variables"

	// Consul template annotations
	// ref: https://bank-vaults.dev/docs/mutating-webhook/consul-template/
	VaultConsulTemplateConfigmapAnnotation              = "vault.security.banzaicloud.io/vault-ct-configmap"
	VaultConsulTemplateImageAnnotation                  = "vault.security.banzaicloud.io/vault-ct-image"
	VaultConsulTemplateOnceAnnotation                   = "vault.security.banzaicloud.io/vault-ct-once"
	VaultConsulTemplatePullPolicyAnnotation             = "vault.security.banzaicloud.io/vault-ct-pull-policy"
	VaultConsulTemplateShareProcessNamespaceAnnotation  = "vault.security.banzaicloud.io/vault-ct-share-process-namespace"
	VaultConsulTemplateCPUAnnotation                    = "vault.security.banzaicloud.io/vault-ct-cpu"
	VaultConsulTemplateMemoryAnnotation                 = "vault.security.banzaicloud.io/vault-ct-memory"
	VaultConsulTemplateSecretsMountPathAnnotation       = "vault.security.banzaicloud.io/vault-ct-secrets-mount-path"
	VaultConsulTemplateInjectInInitcontainersAnnotation = "vault.security.banzaicloud.io/vault-ct-inject-in-initcontainers"

	// Bao annotations
	BaoAddrAnnotation                          = "bao.security.banzaicloud.io/bao-addr"
	BaoImageAnnotation                         = "bao.security.banzaicloud.io/bao-image"
	BaoImagePullPolicyAnnotation               = "bao.security.banzaicloud.io/bao-image-pull-policy"
	BaoRoleAnnotation                          = "bao.security.banzaicloud.io/bao-role"
	BaoPathAnnotation                          = "bao.security.banzaicloud.io/bao-path"
	BaoSkipVerifyAnnotation                    = "bao.security.banzaicloud.io/bao-skip-verify"
	BaoTLSSecretAnnotation                     = "bao.security.banzaicloud.io/bao-tls-secret"
	BaoIgnoreMissingSecretsAnnotation          = "bao.security.banzaicloud.io/bao-ignore-missing-secrets"
	BaoClientTimeoutAnnotation                 = "bao.security.banzaicloud.io/bao-client-timeout"
	BaoTransitKeyIDAnnotation                  = "bao.security.banzaicloud.io/bao-transit-key-id"
	BaoTransitPathAnnotation                   = "bao.security.banzaicloud.io/bao-transit-path"
	BaoAuthMethodAnnotation                    = "bao.security.banzaicloud.io/bao-auth-method"
	BaoTransitBatchSizeAnnotation              = "bao.security.banzaicloud.io/bao-transit-batch-size"
	BaoTokenAuthMountAnnotation                = "bao.security.banzaicloud.io/bao-token-auth-mount"
	BaoServiceaccountAnnotation                = "bao.security.banzaicloud.io/bao-serviceaccount"
	BaoNamespaceAnnotation                     = "bao.security.banzaicloud.io/bao-namespace"
	BaoServiceAccountTokenVolumeNameAnnotation = "bao.security.banzaicloud.io/bao-service-account-token-volume-name"
	BaoLogLevelAnnotation                      = "bao.security.banzaicloud.io/bao-log-level"
	BaoPassthroughAnnotation                   = "bao.security.banzaicloud.io/bao-passthrough"
	BaoFromPathAnnotation                      = "bao.security.banzaicloud.io/bao-from-path"

	// Bao agent annotations
	BaoAgentAnnotation                      = "bao.security.banzaicloud.io/bao-agent"
	BaoAgentConfigmapAnnotation             = "bao.security.banzaicloud.io/bao-agent-configmap"
	BaoAgentOnceAnnotation                  = "bao.security.banzaicloud.io/bao-agent-once"
	BaoAgentShareProcessNamespaceAnnotation = "bao.security.banzaicloud.io/bao-agent-share-process-namespace"
	BaoAgentCPUAnnotation                   = "bao.security.banzaicloud.io/bao-agent-cpu"
	BaoAgentCPULimitAnnotation              = "bao.security.banzaicloud.io/bao-agent-cpu-limit"
	BaoAgentCPURequestAnnotation            = "bao.security.banzaicloud.io/bao-agent-cpu-request"
	BaoAgentMemoryAnnotation                = "bao.security.banzaicloud.io/bao-agent-memory"
	BaoAgentMemoryLimitAnnotation           = "bao.security.banzaicloud.io/bao-agent-memory-limit"
	BaoAgentMemoryRequestAnnotation         = "bao.security.banzaicloud.io/bao-agent-memory-request"
	BaoConfigfilePathAnnotation             = "bao.security.banzaicloud.io/bao-configfile-path"
	BaoAgentEnvVariablesAnnotation          = "bao.security.banzaicloud.io/bao-agent-env-variables"

	// Consul template annotations
	BaoConsulTemplateConfigmapAnnotation              = "bao.security.banzaicloud.io/bao-ct-configmap"
	BaoConsulTemplateImageAnnotation                  = "bao.security.banzaicloud.io/bao-ct-image"
	BaoConsulTemplateOnceAnnotation                   = "bao.security.banzaicloud.io/bao-ct-once"
	BaoConsulTemplatePullPolicyAnnotation             = "bao.security.banzaicloud.io/bao-ct-pull-policy"
	BaoConsulTemplateShareProcessNamespaceAnnotation  = "bao.security.banzaicloud.io/bao-ct-share-process-namespace"
	BaoConsulTemplateCPUAnnotation                    = "bao.security.banzaicloud.io/bao-ct-cpu"
	BaoConsulTemplateMemoryAnnotation                 = "bao.security.banzaicloud.io/bao-ct-memory"
	BaoConsulTemplateSecretsMountPathAnnotation       = "bao.security.banzaicloud.io/bao-ct-secrets-mount-path"
	BaoConsulTemplateInjectInInitcontainersAnnotation = "bao.security.banzaicloud.io/bao-ct-inject-in-initcontainers"
)

func HasVaultPrefix(value string) bool {
	return strings.HasPrefix(value, "vault:") || strings.HasPrefix(value, ">>vault:")
}

func HasBaoPrefix(value string) bool {
	return strings.HasPrefix(value, "bao:") || strings.HasPrefix(value, ">>bao:")
}

func GetPullPolicy(pullPolicyStr string) corev1.PullPolicy {
	switch pullPolicyStr {
	case "Never", "never":
		return corev1.PullNever
	case "Always", "always":
		return corev1.PullAlways
	case "IfNotPresent", "ifnotpresent":
		return corev1.PullIfNotPresent
	}

	return corev1.PullIfNotPresent
}
