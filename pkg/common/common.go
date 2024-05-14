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

// ANNOTATIONS
const (
	// Webhook annotations
	// ref: https://bank-vaults.dev/docs/mutating-webhook/annotations/
	PSPAllowPrivilegeEscalationAnnotation = "secrets-webhook.security.bank-vaults.io/psp-allow-privilege-escalation"
	RunAsNonRootAnnotation                = "secrets-webhook.security.bank-vaults.io/run-as-non-root"
	RunAsUserAnnotation                   = "secrets-webhook.security.bank-vaults.io/run-as-user"
	RunAsGroupAnnotation                  = "secrets-webhook.security.bank-vaults.io/run-as-group"
	ReadOnlyRootFsAnnotation              = "secrets-webhook.security.bank-vaults.io/readonly-root-fs"
	RegistrySkipVerifyAnnotation          = "secrets-webhook.security.bank-vaults.io/registry-skip-verify"
	MutateAnnotation                      = "secrets-webhook.security.bank-vaults.io/mutate"
	MutateProbesAnnotation                = "secrets-webhook.security.bank-vaults.io/mutate-probes"
	ProviderAnnotation                    = "secrets-webhook.security.bank-vaults.io/provider"

	// Secret-init annotations
	SecretInitDaemonAnnotation          = "secrets-webhook.security.bank-vaults.io/secret-init-daemon"
	SecretInitDelayAnnotation           = "secrets-webhook.security.bank-vaults.io/secret-init-delay"
	SecretInitJSONLogAnnotation         = "secrets-webhook.security.bank-vaults.io/secret-init-json-log"
	SecretInitImageAnnotation           = "secrets-webhook.security.bank-vaults.io/secret-init-image"
	SecretInitImagePullPolicyAnnotation = "secrets-webhook.security.bank-vaults.io/secret-init-image-pull-policy"

	// Vault annotations
	VaultAddrAnnotation                          = "secrets-webhook.security.bank-vaults.io/vault-addr"
	VaultImageAnnotation                         = "secrets-webhook.security.bank-vaults.io/vault-image"
	VaultImagePullPolicyAnnotation               = "secrets-webhook.security.bank-vaults.io/vault-image-pull-policy"
	VaultRoleAnnotation                          = "secrets-webhook.security.bank-vaults.io/vault-role"
	VaultPathAnnotation                          = "secrets-webhook.security.bank-vaults.io/vault-path"
	VaultSkipVerifyAnnotation                    = "secrets-webhook.security.bank-vaults.io/vault-skip-verify"
	VaultTLSSecretAnnotation                     = "secrets-webhook.security.bank-vaults.io/vault-tls-secret"
	VaultIgnoreMissingSecretsAnnotation          = "secrets-webhook.security.bank-vaults.io/vault-ignore-missing-secrets"
	VaultClientTimeoutAnnotation                 = "secrets-webhook.security.bank-vaults.io/vault-client-timeout"
	VaultTransitKeyIDAnnotation                  = "secrets-webhook.security.bank-vaults.io/vault-transit-key-id"
	VaultTransitPathAnnotation                   = "secrets-webhook.security.bank-vaults.io/vault-transit-path"
	VaultAuthMethodAnnotation                    = "secrets-webhook.security.bank-vaults.io/vault-auth-method"
	VaultTransitBatchSizeAnnotation              = "secrets-webhook.security.bank-vaults.io/vault-transit-batch-size"
	VaultTokenAuthMountAnnotation                = "secrets-webhook.security.bank-vaults.io/vault-token-auth-mount"
	VaultServiceaccountAnnotation                = "secrets-webhook.security.bank-vaults.io/vault-serviceaccount"
	VaultNamespaceAnnotation                     = "secrets-webhook.security.bank-vaults.io/vault-namespace"
	VaultServiceAccountTokenVolumeNameAnnotation = "secrets-webhook.security.bank-vaults.io/vault-service-account-token-volume-name"
	VaultLogLevelAnnotation                      = "secrets-webhook.security.bank-vaults.io/vault-log-level"
	VaultPassthroughAnnotation                   = "secrets-webhook.security.bank-vaults.io/vault-passthrough"
	VaultFromPathAnnotation                      = "secrets-webhook.security.bank-vaults.io/vault-from-path"

	// Vault agent annotations
	// ref: https://bank-vaults.dev/docs/mutating-webhook/vault-agent-templating/
	VaultAgentAnnotation                      = "secrets-webhook.security.bank-vaults.io/vault-agent"
	VaultAgentConfigmapAnnotation             = "secrets-webhook.security.bank-vaults.io/vault-agent-configmap"
	VaultAgentOnceAnnotation                  = "secrets-webhook.security.bank-vaults.io/vault-agent-once"
	VaultAgentShareProcessNamespaceAnnotation = "secrets-webhook.security.bank-vaults.io/vault-agent-share-process-namespace"
	VaultAgentCPUAnnotation                   = "secrets-webhook.security.bank-vaults.io/vault-agent-cpu"
	VaultAgentCPULimitAnnotation              = "secrets-webhook.security.bank-vaults.io/vault-agent-cpu-limit"
	VaultAgentCPURequestAnnotation            = "secrets-webhook.security.bank-vaults.io/vault-agent-cpu-request"
	VaultAgentMemoryAnnotation                = "secrets-webhook.security.bank-vaults.io/vault-agent-memory"
	VaultAgentMemoryLimitAnnotation           = "secrets-webhook.security.bank-vaults.io/vault-agent-memory-limit"
	VaultAgentMemoryRequestAnnotation         = "secrets-webhook.security.bank-vaults.io/vault-agent-memory-request"
	VaultConfigfilePathAnnotation             = "secrets-webhook.security.bank-vaults.io/vault-configfile-path"
	VaultAgentEnvVariablesAnnotation          = "secrets-webhook.security.bank-vaults.io/vault-agent-env-variables"

	// Consul template annotations
	// ref: https://bank-vaults.dev/docs/mutating-webhook/consul-template/
	VaultConsulTemplateConfigmapAnnotation              = "secrets-webhook.security.bank-vaults.io/vault-ct-configmap"
	VaultConsulTemplateImageAnnotation                  = "secrets-webhook.security.bank-vaults.io/vault-ct-image"
	VaultConsulTemplateOnceAnnotation                   = "secrets-webhook.security.bank-vaults.io/vault-ct-once"
	VaultConsulTemplatePullPolicyAnnotation             = "secrets-webhook.security.bank-vaults.io/vault-ct-pull-policy"
	VaultConsulTemplateShareProcessNamespaceAnnotation  = "secrets-webhook.security.bank-vaults.io/vault-ct-share-process-namespace"
	VaultConsulTemplateCPUAnnotation                    = "secrets-webhook.security.bank-vaults.io/vault-ct-cpu"
	VaultConsulTemplateMemoryAnnotation                 = "secrets-webhook.security.bank-vaults.io/vault-ct-memory"
	VaultConsulTemplateSecretsMountPathAnnotation       = "secrets-webhook.security.bank-vaults.io/vault-ct-secrets-mount-path"
	VaultConsulTemplateInjectInInitcontainersAnnotation = "secrets-webhook.security.bank-vaults.io/vault-ct-inject-in-initcontainers"

	// Bao annotations
	BaoAddrAnnotation                          = "secrets-webhook.security.bank-vaults.io/bao-addr"
	BaoImageAnnotation                         = "secrets-webhook.security.bank-vaults.io/bao-image"
	BaoImagePullPolicyAnnotation               = "secrets-webhook.security.bank-vaults.io/bao-image-pull-policy"
	BaoRoleAnnotation                          = "secrets-webhook.security.bank-vaults.io/bao-role"
	BaoPathAnnotation                          = "secrets-webhook.security.bank-vaults.io/bao-path"
	BaoSkipVerifyAnnotation                    = "secrets-webhook.security.bank-vaults.io/bao-skip-verify"
	BaoTLSSecretAnnotation                     = "secrets-webhook.security.bank-vaults.io/bao-tls-secret"
	BaoIgnoreMissingSecretsAnnotation          = "secrets-webhook.security.bank-vaults.io/bao-ignore-missing-secrets"
	BaoClientTimeoutAnnotation                 = "secrets-webhook.security.bank-vaults.io/bao-client-timeout"
	BaoTransitKeyIDAnnotation                  = "secrets-webhook.security.bank-vaults.io/bao-transit-key-id"
	BaoTransitPathAnnotation                   = "secrets-webhook.security.bank-vaults.io/bao-transit-path"
	BaoAuthMethodAnnotation                    = "secrets-webhook.security.bank-vaults.io/bao-auth-method"
	BaoTransitBatchSizeAnnotation              = "secrets-webhook.security.bank-vaults.io/bao-transit-batch-size"
	BaoTokenAuthMountAnnotation                = "secrets-webhook.security.bank-vaults.io/bao-token-auth-mount"
	BaoServiceaccountAnnotation                = "secrets-webhook.security.bank-vaults.io/bao-serviceaccount"
	BaoNamespaceAnnotation                     = "secrets-webhook.security.bank-vaults.io/bao-namespace"
	BaoServiceAccountTokenVolumeNameAnnotation = "secrets-webhook.security.bank-vaults.io/bao-service-account-token-volume-name"
	BaoLogLevelAnnotation                      = "secrets-webhook.security.bank-vaults.io/bao-log-level"
	BaoPassthroughAnnotation                   = "secrets-webhook.security.bank-vaults.io/bao-passthrough"
	BaoFromPathAnnotation                      = "secrets-webhook.security.bank-vaults.io/bao-from-path"

	// Bao agent annotations
	BaoAgentAnnotation                      = "secrets-webhook.security.bank-vaults.io/bao-agent"
	BaoAgentConfigmapAnnotation             = "secrets-webhook.security.bank-vaults.io/bao-agent-configmap"
	BaoAgentOnceAnnotation                  = "secrets-webhook.security.bank-vaults.io/bao-agent-once"
	BaoAgentShareProcessNamespaceAnnotation = "secrets-webhook.security.bank-vaults.io/bao-agent-share-process-namespace"
	BaoAgentCPUAnnotation                   = "secrets-webhook.security.bank-vaults.io/bao-agent-cpu"
	BaoAgentCPULimitAnnotation              = "secrets-webhook.security.bank-vaults.io/bao-agent-cpu-limit"
	BaoAgentCPURequestAnnotation            = "secrets-webhook.security.bank-vaults.io/bao-agent-cpu-request"
	BaoAgentMemoryAnnotation                = "secrets-webhook.security.bank-vaults.io/bao-agent-memory"
	BaoAgentMemoryLimitAnnotation           = "secrets-webhook.security.bank-vaults.io/bao-agent-memory-limit"
	BaoAgentMemoryRequestAnnotation         = "secrets-webhook.security.bank-vaults.io/bao-agent-memory-request"
	BaoConfigfilePathAnnotation             = "secrets-webhook.security.bank-vaults.io/bao-configfile-path"
	BaoAgentEnvVariablesAnnotation          = "secrets-webhook.security.bank-vaults.io/bao-agent-env-variables"

	// Consul template annotations
	BaoConsulTemplateConfigmapAnnotation              = "secrets-webhook.security.bank-vaults.io/bao-ct-configmap"
	BaoConsulTemplateImageAnnotation                  = "secrets-webhook.security.bank-vaults.io/bao-ct-image"
	BaoConsulTemplateOnceAnnotation                   = "secrets-webhook.security.bank-vaults.io/bao-ct-once"
	BaoConsulTemplatePullPolicyAnnotation             = "secrets-webhook.security.bank-vaults.io/bao-ct-pull-policy"
	BaoConsulTemplateShareProcessNamespaceAnnotation  = "secrets-webhook.security.bank-vaults.io/bao-ct-share-process-namespace"
	BaoConsulTemplateCPUAnnotation                    = "secrets-webhook.security.bank-vaults.io/bao-ct-cpu"
	BaoConsulTemplateMemoryAnnotation                 = "secrets-webhook.security.bank-vaults.io/bao-ct-memory"
	BaoConsulTemplateSecretsMountPathAnnotation       = "secrets-webhook.security.bank-vaults.io/bao-ct-secrets-mount-path"
	BaoConsulTemplateInjectInInitcontainersAnnotation = "secrets-webhook.security.bank-vaults.io/bao-ct-inject-in-initcontainers"
)

// ENVIRONMENT VARIABLES
const (
	// Webhook environment variables
	PSPAllowPrivilegeEscalationEnvVar = "psp_allow_privilege_escalation"
	RunAsNonRootEnvVar                = "run_as_non_root"
	RunAsUserEnvVar                   = "run_as_user"
	RunAsGroupEnvVar                  = "run_as_group"
	ReadonlyRootFSEnvVar              = "readonly_root_fs"
	RegistrySkipVerifyEnvVar          = "registry_skip_verify"
	MutateConfigMapEnvVar             = "mutate_configmap"
	DefaultImagePullSecretEnvVar      = "default_image_pull_secret"
	DefaultImagePullSecretSAEnvVar    = "default_image_pull_secret_service_account"
	DefaultImagePullSecretNSEnvVar    = "default_image_pull_secret_namespace"
	TLSCertFileEnvVar                 = "tls_cert_file"
	TLSPrivateKeyFileEnvVar           = "tls_private_key_file"
	ListenAddressEnvVar               = "listen_address"
	TelemetryListenAddressEnvVar      = "telemetry_listen_address"
	LogLevelEnvVar                    = "log_level"

	// Secret-init environment variables
	SecretInitDaemonEnvVar          = "secret_init_daemon"
	SecretInitDelayEnvVar           = "secret_init_delay"
	SecretInitJSONLogEnvVar         = "secret_init_json_log"
	SecretInitImageEnvVar           = "secret_init_image"
	SecretInitLogServerEnvVar       = "secret_init_log_server"
	SecretInitLogLevelEnvVar        = "secret_init_log_level"
	SecretInitimagePullPolicyEnvVar = "secret_init_image_pull_policy"
	SecretInitCPURequestEnvVar      = "secret_init_cpu_request"
	SecretInitMemoryRequestEnvVar   = "secret_init_memory_request"
	SecretInitCPULimitEnvVar        = "secret_init_cpu_limit"
	SecretInitMemoryLimitEnvVar     = "secret_init_memory_limit"

	// Vault environment variables
	VaultImageEnvVar                      = "vault_image"
	VaultImagePullPolicyEnvVar            = "vault_image_pull_policy"
	VaultCTImageEnvVar                    = "vault_ct_image"
	VaultCTPullPolicyEnvVar               = "vault_ct_pull_policy"
	VaultAddrEnvVar                       = "vault_addr"
	VaultSkipVerifyEnvVar                 = "vault_skip_verify"
	VaultPathEnvVar                       = "vault_path"
	VaultAuthMethodEnvVar                 = "vault_auth_method"
	VaultRoleEnvVar                       = "vault_role"
	VaultTLSSecretEnvVar                  = "vault_tls_secret"
	VaultClientTimeoutEnvVar              = "vault_client_timeout"
	VaultAgentEnvVar                      = "vault_agent"
	VaultCTShareProcessNamespaceEnvVar    = "vault_ct_share_process_namespace"
	VaultIgnoreMissingSecretsEnvVar       = "vault_ignore_missing_secrets"
	VaultPassthroughEnvVar                = "vault_passthrough"
	VaultAgentShareProcessNamespaceEnvVar = "vault_agent_share_process_namespace"
	VaultLogLevelEnvVar                   = "vault_log_level"
	VaultNamespaceEnvVar                  = "vault_namespace"
	VaultTransitKeyIDEnvVar               = "vault_transit_key_id"
	VaultTransitPathEnvVar                = "vault_transit_path"
	VaultTransitBatchSizeEnvVar           = "vault_transit_batch_size"
	VaultTokenEnvVar                      = "vault_token"
	VaultSAEnvVar                         = "vault_serviceaccount"
	VaultSATokenVolumeNameEnvVar          = "vault_service_account_token_volume_name"

	// Bao environment variables
	BaoImageEnvVar                      = "bao_image"
	BaoImagePullPolicyEnvVar            = "bao_image_pull_policy"
	BaoCTImageEnvVar                    = "bao_ct_image"
	BaoCTPullPolicyEnvVar               = "bao_ct_pull_policy"
	BaoAddrEnvVar                       = "bao_addr"
	BaoSkipVerifyEnvVar                 = "bao_skip_verify"
	BaoPathEnvVar                       = "bao_path"
	BaoAuthMethodEnvVar                 = "bao_auth_method"
	BaoRoleEnvVar                       = "bao_role"
	BaoTLSSecretEnvVar                  = "bao_tls_secret"
	BaoClientTimeoutEnvVar              = "bao_client_timeout"
	BaoAgentEnvVar                      = "bao_agent"
	BaoCTShareProcessNamespaceEnvVar    = "bao_ct_share_process_namespace"
	BaoIgnoreMissingSecretsEnvVar       = "bao_ignore_missing_secrets"
	BaoPassthroughEnvVar                = "bao_passthrough"
	BaoAgentShareProcessNamespaceEnvVar = "bao_agent_share_process_namespace"
	BaoLogLevelEnvVar                   = "bao_log_level"
	BaoNamespaceEnvVar                  = "bao_namespace"
	BaoTransitKeyIDEnvVar               = "bao_transit_key_id"
	BaoTransitPathEnvVar                = "bao_transit_path"
	BaoTransitBatchSizeEnvVar           = "bao_transit_batch_size"
	BaoTokenEnvVar                      = "bao_token"
	BaoSAEnvVar                         = "bao_serviceaccount"
	BaoSATokenVolumeNameEnvVar          = "bao_service_account_token_volume_name"
)

// DEPRECATED ANNOTATIONS
const (
	// Webhook annotations
	PSPAllowPrivilegeEscalationAnnotationDeprecated = "vault.security.banzaicloud.io/psp-allow-privilege-escalation"
	RunAsNonRootAnnotationDeprecated                = "vault.security.banzaicloud.io/run-as-non-root"
	RunAsUserAnnotationDeprecated                   = "vault.security.banzaicloud.io/run-as-user"
	RunAsGroupAnnotationDeprecated                  = "vault.security.banzaicloud.io/run-as-group"
	ReadOnlyRootFsAnnotationDeprecated              = "vault.security.banzaicloud.io/readonly-root-fs"
	RegistrySkipVerifyAnnotationDeprecated          = "vault.security.banzaicloud.io/registry-skip-verify"
	MutateAnnotationDeprecated                      = "vault.security.banzaicloud.io/mutate"
	MutateProbesAnnotationDeprecated                = "vault.security.banzaicloud.io/mutate-probes"

	// Vault-env annotations
	VaultEnvDaemonAnnotationDeprecated          = "vault.security.banzaicloud.io/vault-env-daemon"
	VaultEnvDelayAnnotationDeprecated           = "vault.security.banzaicloud.io/vault-env-delay"
	VaultEnvEnableJSONLogAnnotationDeprecated   = "vault.security.banzaicloud.io/enable-json-log"
	VaultEnvImageAnnotationDeprecated           = "vault.security.banzaicloud.io/vault-env-image"
	VaultEnvImagePullPolicyAnnotationDeprecated = "vault.security.banzaicloud.io/vault-env-image-pull-policy"

	// Vault annotations
	VaultAddrAnnotationDeprecated                          = "vault.security.banzaicloud.io/vault-addr"
	VaultImageAnnotationDeprecated                         = "vault.security.banzaicloud.io/vault-image"
	VaultImagePullPolicyAnnotationDeprecated               = "vault.security.banzaicloud.io/vault-image-pull-policy"
	VaultRoleAnnotationDeprecated                          = "vault.security.banzaicloud.io/vault-role"
	VaultPathAnnotationDeprecated                          = "vault.security.banzaicloud.io/vault-path"
	VaultSkipVerifyAnnotationDeprecated                    = "vault.security.banzaicloud.io/vault-skip-verify"
	VaultTLSSecretAnnotationDeprecated                     = "vault.security.banzaicloud.io/vault-tls-secret"
	VaultIgnoreMissingSecretsAnnotationDeprecated          = "vault.security.banzaicloud.io/vault-ignore-missing-secrets"
	VaultClientTimeoutAnnotationDeprecated                 = "vault.security.banzaicloud.io/vault-client-timeout"
	VaultTransitKeyIDAnnotationDeprecated                  = "vault.security.banzaicloud.io/transit-key-id"
	VaultTransitPathAnnotationDeprecated                   = "vault.security.banzaicloud.io/transit-path"
	VaultAuthMethodAnnotationDeprecated                    = "vault.security.banzaicloud.io/vault-auth-method"
	VaultTransitBatchSizeAnnotationDeprecated              = "vault.security.banzaicloud.io/transit-batch-size"
	VaultTokenAuthMountAnnotationDeprecated                = "vault.security.banzaicloud.io/token-auth-mount"
	VaultServiceaccountAnnotationDeprecated                = "vault.security.banzaicloud.io/vault-serviceaccount"
	VaultNamespaceAnnotationDeprecated                     = "vault.security.banzaicloud.io/vault-namespace"
	VaultServiceAccountTokenVolumeNameAnnotationDeprecated = "vault.security.banzaicloud.io/service-account-token-volume-name"
	VaultLogLevelAnnotationDeprecated                      = "vault.security.banzaicloud.io/log-level"
	VaultEnvPassthroughAnnotationDeprecated                = "vault.security.banzaicloud.io/vault-env-passthrough"
	VaultEnvFromPathAnnotationDeprecated                   = "vault.security.banzaicloud.io/vault-env-from-path"

	// Vault agent annotations
	VaultAgentAnnotationDeprecated                      = "vault.security.banzaicloud.io/vault-agent"
	VaultAgentConfigmapAnnotationDeprecated             = "vault.security.banzaicloud.io/vault-agent-configmap"
	VaultAgentOnceAnnotationDeprecated                  = "vault.security.banzaicloud.io/vault-agent-once"
	VaultAgentShareProcessNamespaceAnnotationDeprecated = "vault.security.banzaicloud.io/vault-agent-share-process-namespace"
	VaultAgentCPUAnnotationDeprecated                   = "vault.security.banzaicloud.io/vault-agent-cpu"
	VaultAgentCPULimitAnnotationDeprecated              = "vault.security.banzaicloud.io/vault-agent-cpu-limit"
	VaultAgentCPURequestAnnotationDeprecated            = "vault.security.banzaicloud.io/vault-agent-cpu-request"
	VaultAgentMemoryAnnotationDeprecated                = "vault.security.banzaicloud.io/vault-agent-memory"
	VaultAgentMemoryLimitAnnotationDeprecated           = "vault.security.banzaicloud.io/vault-agent-memory-limit"
	VaultAgentMemoryRequestAnnotationDeprecated         = "vault.security.banzaicloud.io/vault-agent-memory-request"
	VaultConfigfilePathAnnotationDeprecated             = "vault.security.banzaicloud.io/vault-configfile-path"
	VaultAgentEnvVariablesAnnotationDeprecated          = "vault.security.banzaicloud.io/vault-agent-env-variables"

	// Consul template annotations
	VaultConsulTemplateConfigmapAnnotationDeprecated              = "vault.security.banzaicloud.io/vault-ct-configmap"
	VaultConsulTemplateImageAnnotationDeprecated                  = "vault.security.banzaicloud.io/vault-ct-image"
	VaultConsulTemplateOnceAnnotationDeprecated                   = "vault.security.banzaicloud.io/vault-ct-once"
	VaultConsulTemplatePullPolicyAnnotationDeprecated             = "vault.security.banzaicloud.io/vault-ct-pull-policy"
	VaultConsulTemplateShareProcessNamespaceAnnotationDeprecated  = "vault.security.banzaicloud.io/vault-ct-share-process-namespace"
	VaultConsulTemplateCPUAnnotationDeprecated                    = "vault.security.banzaicloud.io/vault-ct-cpu"
	VaultConsulTemplateMemoryAnnotationDeprecated                 = "vault.security.banzaicloud.io/vault-ct-memory"
	VaultConsulTemplateSecretsMountPathAnnotationDeprecated       = "vault.security.banzaicloud.io/vault-ct-secrets-mount-path"
	VaultConsulTemplateInjectInInitcontainersAnnotationDeprecated = "vault.security.banzaicloud.io/vault-ct-inject-in-initcontainers"
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
