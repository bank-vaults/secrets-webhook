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

import corev1 "k8s.io/api/core/v1"

// ANNOTATIONS
const (
	WebhookAnnotationPrefix = "secrets-webhook.security.bank-vaults.io/"

	// Webhook annotations
	// ref: https://bank-vaults.dev/docs/mutating-webhook/annotations/
	PSPAllowPrivilegeEscalationAnnotation = WebhookAnnotationPrefix + "psp-allow-privilege-escalation"
	RunAsNonRootAnnotation                = WebhookAnnotationPrefix + "run-as-non-root"
	RunAsUserAnnotation                   = WebhookAnnotationPrefix + "run-as-user"
	RunAsGroupAnnotation                  = WebhookAnnotationPrefix + "run-as-group"
	ReadOnlyRootFsAnnotation              = WebhookAnnotationPrefix + "readonly-root-fs"
	RegistrySkipVerifyAnnotation          = WebhookAnnotationPrefix + "registry-skip-verify"
	MutateAnnotation                      = WebhookAnnotationPrefix + "mutate"
	MutateProbesAnnotation                = WebhookAnnotationPrefix + "mutate-probes"
	ProviderAnnotation                    = WebhookAnnotationPrefix + "provider"

	// Secret-init annotations
	SecretInitDaemonAnnotation          = WebhookAnnotationPrefix + "secret-init-daemon"
	SecretInitDelayAnnotation           = WebhookAnnotationPrefix + "secret-init-delay"
	SecretInitJSONLogAnnotation         = WebhookAnnotationPrefix + "secret-init-json-log"
	SecretInitImageAnnotation           = WebhookAnnotationPrefix + "secret-init-image"
	SecretInitImagePullPolicyAnnotation = WebhookAnnotationPrefix + "secret-init-image-pull-policy"

	// Vault annotations
	VaultAddrAnnotation                          = WebhookAnnotationPrefix + "vault-addr"
	VaultImageAnnotation                         = WebhookAnnotationPrefix + "vault-image"
	VaultImagePullPolicyAnnotation               = WebhookAnnotationPrefix + "vault-image-pull-policy"
	VaultRoleAnnotation                          = WebhookAnnotationPrefix + "vault-role"
	VaultPathAnnotation                          = WebhookAnnotationPrefix + "vault-path"
	VaultSkipVerifyAnnotation                    = WebhookAnnotationPrefix + "vault-skip-verify"
	VaultTLSSecretAnnotation                     = WebhookAnnotationPrefix + "vault-tls-secret"
	VaultIgnoreMissingSecretsAnnotation          = WebhookAnnotationPrefix + "vault-ignore-missing-secrets"
	VaultClientTimeoutAnnotation                 = WebhookAnnotationPrefix + "vault-client-timeout"
	VaultTransitKeyIDAnnotation                  = WebhookAnnotationPrefix + "vault-transit-key-id"
	VaultTransitPathAnnotation                   = WebhookAnnotationPrefix + "vault-transit-path"
	VaultAuthMethodAnnotation                    = WebhookAnnotationPrefix + "vault-auth-method"
	VaultTransitBatchSizeAnnotation              = WebhookAnnotationPrefix + "vault-transit-batch-size"
	VaultTokenAuthMountAnnotation                = WebhookAnnotationPrefix + "vault-token-auth-mount"
	VaultServiceaccountAnnotation                = WebhookAnnotationPrefix + "vault-serviceaccount"
	VaultNamespaceAnnotation                     = WebhookAnnotationPrefix + "vault-namespace"
	VaultServiceAccountTokenVolumeNameAnnotation = WebhookAnnotationPrefix + "vault-service-account-token-volume-name"
	VaultLogLevelAnnotation                      = WebhookAnnotationPrefix + "vault-log-level"
	VaultPassthroughAnnotation                   = WebhookAnnotationPrefix + "vault-passthrough"
	VaultFromPathAnnotation                      = WebhookAnnotationPrefix + "vault-from-path"

	// Vault agent annotations
	// ref: https://bank-vaults.dev/docs/mutating-webhook/vault-agent-templating/
	VaultAgentAnnotation                      = WebhookAnnotationPrefix + "vault-agent"
	VaultAgentConfigmapAnnotation             = WebhookAnnotationPrefix + "vault-agent-configmap"
	VaultAgentOnceAnnotation                  = WebhookAnnotationPrefix + "vault-agent-once"
	VaultAgentShareProcessNamespaceAnnotation = WebhookAnnotationPrefix + "vault-agent-share-process-namespace"
	VaultAgentCPUAnnotation                   = WebhookAnnotationPrefix + "vault-agent-cpu"
	VaultAgentCPULimitAnnotation              = WebhookAnnotationPrefix + "vault-agent-cpu-limit"
	VaultAgentCPURequestAnnotation            = WebhookAnnotationPrefix + "vault-agent-cpu-request"
	VaultAgentMemoryAnnotation                = WebhookAnnotationPrefix + "vault-agent-memory"
	VaultAgentMemoryLimitAnnotation           = WebhookAnnotationPrefix + "vault-agent-memory-limit"
	VaultAgentMemoryRequestAnnotation         = WebhookAnnotationPrefix + "vault-agent-memory-request"
	VaultConfigfilePathAnnotation             = WebhookAnnotationPrefix + "vault-configfile-path"
	VaultAgentEnvVariablesAnnotation          = WebhookAnnotationPrefix + "vault-agent-env-variables"

	// Consul template annotations
	// ref: https://bank-vaults.dev/docs/mutating-webhook/consul-template/
	VaultConsulTemplateConfigmapAnnotation              = WebhookAnnotationPrefix + "vault-ct-configmap"
	VaultConsulTemplateImageAnnotation                  = WebhookAnnotationPrefix + "vault-ct-image"
	VaultConsulTemplateOnceAnnotation                   = WebhookAnnotationPrefix + "vault-ct-once"
	VaultConsulTemplatePullPolicyAnnotation             = WebhookAnnotationPrefix + "vault-ct-pull-policy"
	VaultConsulTemplateShareProcessNamespaceAnnotation  = WebhookAnnotationPrefix + "vault-ct-share-process-namespace"
	VaultConsulTemplateCPUAnnotation                    = WebhookAnnotationPrefix + "vault-ct-cpu"
	VaultConsulTemplateMemoryAnnotation                 = WebhookAnnotationPrefix + "vault-ct-memory"
	VaultConsulTemplateSecretsMountPathAnnotation       = WebhookAnnotationPrefix + "vault-ct-secrets-mount-path"
	VaultConsulTemplateInjectInInitcontainersAnnotation = WebhookAnnotationPrefix + "vault-ct-inject-in-initcontainers"

	// Bao annotations
	BaoAddrAnnotation                          = WebhookAnnotationPrefix + "bao-addr"
	BaoImageAnnotation                         = WebhookAnnotationPrefix + "bao-image"
	BaoImagePullPolicyAnnotation               = WebhookAnnotationPrefix + "bao-image-pull-policy"
	BaoRoleAnnotation                          = WebhookAnnotationPrefix + "bao-role"
	BaoPathAnnotation                          = WebhookAnnotationPrefix + "bao-path"
	BaoSkipVerifyAnnotation                    = WebhookAnnotationPrefix + "bao-skip-verify"
	BaoTLSSecretAnnotation                     = WebhookAnnotationPrefix + "bao-tls-secret"
	BaoIgnoreMissingSecretsAnnotation          = WebhookAnnotationPrefix + "bao-ignore-missing-secrets"
	BaoClientTimeoutAnnotation                 = WebhookAnnotationPrefix + "bao-client-timeout"
	BaoTransitKeyIDAnnotation                  = WebhookAnnotationPrefix + "bao-transit-key-id"
	BaoTransitPathAnnotation                   = WebhookAnnotationPrefix + "bao-transit-path"
	BaoAuthMethodAnnotation                    = WebhookAnnotationPrefix + "bao-auth-method"
	BaoTransitBatchSizeAnnotation              = WebhookAnnotationPrefix + "bao-transit-batch-size"
	BaoTokenAuthMountAnnotation                = WebhookAnnotationPrefix + "bao-token-auth-mount"
	BaoServiceaccountAnnotation                = WebhookAnnotationPrefix + "bao-serviceaccount"
	BaoNamespaceAnnotation                     = WebhookAnnotationPrefix + "bao-namespace"
	BaoServiceAccountTokenVolumeNameAnnotation = WebhookAnnotationPrefix + "bao-service-account-token-volume-name"
	BaoLogLevelAnnotation                      = WebhookAnnotationPrefix + "bao-log-level"
	BaoPassthroughAnnotation                   = WebhookAnnotationPrefix + "bao-passthrough"
	BaoFromPathAnnotation                      = WebhookAnnotationPrefix + "bao-from-path"

	// Bao agent annotations
	BaoAgentAnnotation                      = WebhookAnnotationPrefix + "bao-agent"
	BaoAgentConfigmapAnnotation             = WebhookAnnotationPrefix + "bao-agent-configmap"
	BaoAgentOnceAnnotation                  = WebhookAnnotationPrefix + "bao-agent-once"
	BaoAgentShareProcessNamespaceAnnotation = WebhookAnnotationPrefix + "bao-agent-share-process-namespace"
	BaoAgentCPUAnnotation                   = WebhookAnnotationPrefix + "bao-agent-cpu"
	BaoAgentCPULimitAnnotation              = WebhookAnnotationPrefix + "bao-agent-cpu-limit"
	BaoAgentCPURequestAnnotation            = WebhookAnnotationPrefix + "bao-agent-cpu-request"
	BaoAgentMemoryAnnotation                = WebhookAnnotationPrefix + "bao-agent-memory"
	BaoAgentMemoryLimitAnnotation           = WebhookAnnotationPrefix + "bao-agent-memory-limit"
	BaoAgentMemoryRequestAnnotation         = WebhookAnnotationPrefix + "bao-agent-memory-request"
	BaoConfigfilePathAnnotation             = WebhookAnnotationPrefix + "bao-configfile-path"
	BaoAgentEnvVariablesAnnotation          = WebhookAnnotationPrefix + "bao-agent-env-variables"

	// Consul template annotations
	BaoConsulTemplateConfigmapAnnotation              = WebhookAnnotationPrefix + "bao-ct-configmap"
	BaoConsulTemplateImageAnnotation                  = WebhookAnnotationPrefix + "bao-ct-image"
	BaoConsulTemplateOnceAnnotation                   = WebhookAnnotationPrefix + "bao-ct-once"
	BaoConsulTemplatePullPolicyAnnotation             = WebhookAnnotationPrefix + "bao-ct-pull-policy"
	BaoConsulTemplateShareProcessNamespaceAnnotation  = WebhookAnnotationPrefix + "bao-ct-share-process-namespace"
	BaoConsulTemplateCPUAnnotation                    = WebhookAnnotationPrefix + "bao-ct-cpu"
	BaoConsulTemplateMemoryAnnotation                 = WebhookAnnotationPrefix + "bao-ct-memory"
	BaoConsulTemplateSecretsMountPathAnnotation       = WebhookAnnotationPrefix + "bao-ct-secrets-mount-path"
	BaoConsulTemplateInjectInInitcontainersAnnotation = WebhookAnnotationPrefix + "bao-ct-inject-in-initcontainers"

	// AWS annotations
	AWSRegionAnnotation                = WebhookAnnotationPrefix + "aws-region"
	AWSLoadFromSecret                  = WebhookAnnotationPrefix + "aws-load-from-secret"
	AWSCredentialsNamespaceAnnotation  = WebhookAnnotationPrefix + "credentials-namespace"
	AWSCredentialsSecretNameAnnotation = WebhookAnnotationPrefix + "credentials-secret-name"
	AWSTLSSecretARNAnnotation          = WebhookAnnotationPrefix + "aws-tls-secret-arn"
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
	ProviderEnvVar                    = "provider"

	// Secret-init environment variables
	SecretInitDaemonEnvVar          = "secret_init_daemon"
	SecretInitDelayEnvVar           = "secret_init_delay"
	SecretInitJSONLogEnvVar         = "secret_init_json_log"
	SecretInitImageEnvVar           = "secret_init_image"
	SecretInitLogServerEnvVar       = "secret_init_log_server"
	SecretInitLogLevelEnvVar        = "secret_init_log_level"
	SecretInitImagePullPolicyEnvVar = "secret_init_image_pull_policy"
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

	// AWS environment variables
	AWSRegionEnvVar                = "aws_region"
	AWSLoadFromSecretEnvVar        = "aws_load_from_secret"
	AWSCredentialsNamespaceEnvVar  = "aws_credentials_namespace"
	AWSCredentialsSecretNameEnvVar = "aws_credentials_secret_name"
	AWSTLSSecretARNEnvVar          = "aws_tls_secret_arn"
)

// DEPRECATED ANNOTATIONS AND ENVIRONMENT VARIABLES
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

	// Vault-env environment variables
	VaultEnvDaemonEnvVarDeprecated          = "vault_env_daemon"
	VaultEnvDelayEnvVarDeprecated           = "vault_env_delay"
	VaultEnvPassthroughEnvVarDeprecated     = "vault_env_passthrough"
	VaultEnvEnableJSONLogEnvVarDeprecated   = "enable_json_log"
	VaultEnvImageEnvVarDeprecated           = "vault_env_image"
	VaultEnvLogServerEnvVarDeprecated       = "VAULT_ENV_LOG_SERVER"
	VaultEnvImagePullPolicyEnvVarDeprecated = "vault_env_pull_policy"
	VaultEnvCPURequestEnvVarDeprecated      = "VAULT_ENV_CPU_REQUEST"
	VaultEnvMemoryRequestEnvVarDeprecated   = "VAULT_ENV_MEMORY_REQUEST"
	VaultEnvCPULimitEnvVarDeprecated        = "VAULT_ENV_CPU_LIMIT"
	VaultEnvMemoryLimitEnvVarDeprecated     = "VAULT_ENV_MEMORY_LIMIT"

	// Vault environment variables
	VaultSATokenVolumeNameEnvVarDeprecated = "SERVICE_ACCOUNT_TOKEN_VOLUME_NAME"
	VaultTransitKeyIDEnvVarDeprecated      = "transit_key_id"
	VaultTransitPathEnvVarDeprecated       = "transit_path"
	VaultTransitBatchSizeEnvVarDeprecated  = "transit_batch_size"
	VaultNamespaceEnvVarDeprecated         = "VAULT_NAMESPACE"
)

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
