// Copyright © 2021 Banzai Cloud
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

package webhook

import (
	"strconv"
	"time"

	"github.com/slok/kubewebhook/v2/pkg/model"
	"github.com/spf13/viper"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/bank-vaults/secrets-webhook/pkg/common"
)

// Config represents the configuration for the webhook
type Config struct {
	PspAllowPrivilegeEscalation bool
	RunAsNonRoot                bool
	RunAsUser                   int64
	RunAsGroup                  int64
	ReadOnlyRootFilesystem      bool
	RegistrySkipVerify          bool
	Mutate                      bool
	MutateProbes                bool
}

// SecretInitConfig represents the configuration for the secret-init container
type SecretInitConfig struct {
	Daemon          bool
	Delay           time.Duration
	LogLevel        string
	JSONLog         string
	Image           string
	ImagePullPolicy corev1.PullPolicy
	LogServer       string
	CPURequest      resource.Quantity
	MemoryRequest   resource.Quantity
	CPULimit        resource.Quantity
	MemoryLimit     resource.Quantity
}

// VaultConfig represents vault options
type VaultConfig struct {
	ObjectNamespace               string
	Addr                          string
	AuthMethod                    string
	Role                          string
	Path                          string
	SkipVerify                    bool
	TLSSecret                     string
	ClientTimeout                 time.Duration
	UseAgent                      bool
	TransitKeyID                  string
	TransitPath                   string
	TransitBatchSize              int
	CtConfigMap                   string
	CtImage                       string
	CtInjectInInitcontainers      bool
	CtOnce                        bool
	CtImagePullPolicy             corev1.PullPolicy
	CtShareProcess                bool
	CtShareProcessDefault         string
	CtCPU                         resource.Quantity
	CtMemory                      resource.Quantity
	ConfigfilePath                string
	AgentConfigMap                string
	AgentOnce                     bool
	AgentShareProcess             bool
	AgentShareProcessDefault      string
	AgentCPULimit                 resource.Quantity
	AgentMemoryLimit              resource.Quantity
	AgentCPURequest               resource.Quantity
	AgentMemoryRequest            resource.Quantity
	AgentImage                    string
	AgentImagePullPolicy          corev1.PullPolicy
	AgentEnvVariables             string
	ServiceAccountTokenVolumeName string
	TokenAuthMount                string
	VaultNamespace                string
	VaultServiceAccount           string
	Token                         string
	IgnoreMissingSecrets          string
	Passthrough                   string
	LogLevel                      string
	FromPath                      string
}

func parseConfig(obj metav1.Object) Config {
	Config := Config{}

	annotations := obj.GetAnnotations()

	if val, ok := annotations[common.MutateAnnotation]; ok {
		Config.Mutate, _ = strconv.ParseBool(val)
	}

	if val, ok := annotations[common.PSPAllowPrivilegeEscalationAnnotation]; ok {
		Config.PspAllowPrivilegeEscalation, _ = strconv.ParseBool(val)
	}

	if val, ok := annotations[common.RunAsNonRootAnnotation]; ok {
		Config.RunAsNonRoot, _ = strconv.ParseBool(val)
	}

	if val, ok := annotations[common.RunAsUserAnnotation]; ok {
		Config.RunAsUser, _ = strconv.ParseInt(val, 10, 64)
	}

	if val, ok := annotations[common.RunAsGroupAnnotation]; ok {
		Config.RunAsGroup, _ = strconv.ParseInt(val, 10, 64)
	}

	if val, ok := annotations[common.ReadOnlyRootFsAnnotation]; ok {
		Config.ReadOnlyRootFilesystem, _ = strconv.ParseBool(val)
	}

	if val, ok := annotations[common.RegistrySkipVerifyAnnotation]; ok {
		Config.RegistrySkipVerify, _ = strconv.ParseBool(val)
	}

	if val, ok := annotations[common.MutateProbesAnnotation]; ok {
		Config.MutateProbes, _ = strconv.ParseBool(val)
	}

	return Config
}

func parseSecretInitConfig(obj metav1.Object) SecretInitConfig {
	secretInitConfig := SecretInitConfig{}

	annotations := obj.GetAnnotations()

	if val, ok := annotations[common.SecretInitDaemonAnnotation]; ok {
		secretInitConfig.Daemon, _ = strconv.ParseBool(val)
	} else {
		secretInitConfig.Daemon, _ = strconv.ParseBool(viper.GetString("secret_init_daemon"))
	}

	if val, ok := annotations[common.SecretInitDelayAnnotation]; ok {
		secretInitConfig.Delay, _ = time.ParseDuration(val)
	} else {
		secretInitConfig.Delay, _ = time.ParseDuration(viper.GetString("secret_init_delay"))
	}

	if val, ok := annotations[common.SecretInitJSONLogAnnotation]; ok {
		secretInitConfig.JSONLog = val
	} else {
		secretInitConfig.JSONLog = viper.GetString("secret_init_json_log")
	}

	if val, ok := annotations[common.SecretInitImageAnnotation]; ok {
		secretInitConfig.Image = val
	} else {
		secretInitConfig.Image = viper.GetString("secret_init_image")
	}

	secretInitConfig.LogServer = viper.GetString("SECRET_INIT_LOG_SERVER")

	secretInitConfig.LogLevel = viper.GetString("SECRET_INIT_LOG_LEVEL")

	if val, ok := annotations[common.SecretInitImagePullPolicyAnnotation]; ok {
		secretInitConfig.ImagePullPolicy = getPullPolicy(val)
	} else {
		secretInitConfig.ImagePullPolicy = getPullPolicy(viper.GetString("secret_init_image_pull_policy"))
	}

	if val, err := resource.ParseQuantity(viper.GetString("SECRET_INIT_CPU_REQUEST")); err == nil {
		secretInitConfig.CPURequest = val
	} else {
		secretInitConfig.CPURequest = resource.MustParse("50m")
	}

	if val, err := resource.ParseQuantity(viper.GetString("SECRET_INIT_MEMORY_REQUEST")); err == nil {
		secretInitConfig.MemoryRequest = val
	} else {
		secretInitConfig.MemoryRequest = resource.MustParse("64Mi")
	}

	if val, err := resource.ParseQuantity(viper.GetString("SECRET_INIT_CPU_LIMIT")); err == nil {
		secretInitConfig.CPULimit = val
	} else {
		secretInitConfig.CPULimit = resource.MustParse("250m")
	}

	if val, err := resource.ParseQuantity(viper.GetString("SECRET_INIT_MEMORY_LIMIT")); err == nil {
		secretInitConfig.MemoryLimit = val
	} else {
		secretInitConfig.MemoryLimit = resource.MustParse("64Mi")
	}

	return secretInitConfig
}

func parseVaultConfig(obj metav1.Object, ar *model.AdmissionReview) VaultConfig {
	vaultConfig := VaultConfig{
		ObjectNamespace: ar.Namespace,
	}

	annotations := obj.GetAnnotations()

	if val, ok := annotations[common.VaultAddrAnnotation]; ok {
		vaultConfig.Addr = val
	} else {
		vaultConfig.Addr = viper.GetString("vault_addr")
	}

	if val, ok := annotations[common.VaultRoleAnnotation]; ok {
		vaultConfig.Role = val
	} else {
		if val := viper.GetString("vault_role"); val != "" {
			vaultConfig.Role = val
		} else {
			switch p := obj.(type) {
			case *corev1.Pod:
				vaultConfig.Role = p.Spec.ServiceAccountName
			default:
				vaultConfig.Role = "default"
			}
		}
	}

	if val, ok := annotations[common.VaultAuthMethodAnnotation]; ok {
		vaultConfig.AuthMethod = val
	} else {
		vaultConfig.AuthMethod = viper.GetString("vault_auth_method")
	}

	if val, ok := annotations[common.VaultPathAnnotation]; ok {
		vaultConfig.Path = val
	} else {
		vaultConfig.Path = viper.GetString("vault_path")
	}

	// TODO: Check for flag to verify we want to use namespace-local SAs instead of the vault webhook namespaces SA
	if val, ok := annotations[common.VaultServiceaccountAnnotation]; ok {
		vaultConfig.VaultServiceAccount = val
	} else {
		vaultConfig.VaultServiceAccount = viper.GetString("vault_serviceaccount")
	}

	if val, ok := annotations[common.VaultSkipVerifyAnnotation]; ok {
		vaultConfig.SkipVerify, _ = strconv.ParseBool(val)
	} else {
		vaultConfig.SkipVerify = viper.GetBool("vault_skip_verify")
	}

	if val, ok := annotations[common.VaultTLSSecretAnnotation]; ok {
		vaultConfig.TLSSecret = val
	} else {
		vaultConfig.TLSSecret = viper.GetString("vault_tls_secret")
	}

	if val, ok := annotations[common.VaultClientTimeoutAnnotation]; ok {
		vaultConfig.ClientTimeout, _ = time.ParseDuration(val)
	} else {
		vaultConfig.ClientTimeout, _ = time.ParseDuration(viper.GetString("vault_client_timeout"))
	}

	if val, ok := annotations[common.VaultAgentAnnotation]; ok {
		vaultConfig.UseAgent, _ = strconv.ParseBool(val)
	} else {
		vaultConfig.UseAgent, _ = strconv.ParseBool(viper.GetString("vault_agent"))
	}

	if val, ok := annotations[common.VaultConsulTemplateConfigmapAnnotation]; ok {
		vaultConfig.CtConfigMap = val
	} else {
		vaultConfig.CtConfigMap = ""
	}

	if val, ok := annotations[common.ServiceAccountTokenVolumeNameAnnotation]; ok {
		vaultConfig.ServiceAccountTokenVolumeName = val
	} else if viper.GetString("SERVICE_ACCOUNT_TOKEN_VOLUME_NAME") != "" {
		vaultConfig.ServiceAccountTokenVolumeName = viper.GetString("SERVICE_ACCOUNT_TOKEN_VOLUME_NAME")
	} else {
		vaultConfig.ServiceAccountTokenVolumeName = "/var/run/secrets/kubernetes.io/serviceaccount"
	}

	if val, ok := annotations[common.VaultConsulTemplateImageAnnotation]; ok {
		vaultConfig.CtImage = val
	} else {
		vaultConfig.CtImage = viper.GetString("vault_ct_image")
	}

	if val, ok := annotations[common.VaultIgnoreMissingSecretsAnnotation]; ok {
		vaultConfig.IgnoreMissingSecrets = val
	} else {
		vaultConfig.IgnoreMissingSecrets = viper.GetString("vault_ignore_missing_secrets")
	}
	if val, ok := annotations[common.VaultPassthroughAnnotation]; ok {
		vaultConfig.Passthrough = val
	} else {
		vaultConfig.Passthrough = viper.GetString("vault_passthrough")
	}
	if val, ok := annotations[common.VaultConfigfilePathAnnotation]; ok {
		vaultConfig.ConfigfilePath = val
	} else if val, ok := annotations[common.VaultConsuleTemplateSecretsMountPathAnnotation]; ok {
		vaultConfig.ConfigfilePath = val
	} else {
		vaultConfig.ConfigfilePath = "/vault/secrets"
	}

	if val, ok := annotations[common.VaultConsulTemplatePullPolicyAnnotation]; ok {
		vaultConfig.CtImagePullPolicy = getPullPolicy(val)
	} else {
		vaultConfig.CtImagePullPolicy = getPullPolicy(viper.GetString("vault_ct_pull_policy"))
	}

	if val, ok := annotations[common.VaultConsulTemplateOnceAnnotation]; ok {
		vaultConfig.CtOnce, _ = strconv.ParseBool(val)
	} else {
		vaultConfig.CtOnce = false
	}

	if val, err := resource.ParseQuantity(annotations[common.VaultConsulTemplateCPUAnnotation]); err == nil {
		vaultConfig.CtCPU = val
	} else {
		vaultConfig.CtCPU = resource.MustParse("100m")
	}

	if val, err := resource.ParseQuantity(annotations[common.VaultConsulTemplateMemoryAnnotation]); err == nil {
		vaultConfig.CtMemory = val
	} else {
		vaultConfig.CtMemory = resource.MustParse("128Mi")
	}

	if val, ok := annotations[common.VaultConsulTemplateShareProcessNamespaceAnnotation]; ok {
		vaultConfig.CtShareProcessDefault = "found"
		vaultConfig.CtShareProcess, _ = strconv.ParseBool(val)
	} else {
		vaultConfig.CtShareProcessDefault = "empty"
		vaultConfig.CtShareProcess = false
	}

	if val, ok := annotations[common.LogLevelAnnotation]; ok {
		vaultConfig.LogLevel = val
	} else {
		vaultConfig.LogLevel = viper.GetString("vault_log_level")
	}

	if val, ok := annotations[common.TransitKeyIDAnnotation]; ok {
		vaultConfig.TransitKeyID = val
	} else {
		vaultConfig.TransitKeyID = viper.GetString("transit_key_id")
	}

	if val, ok := annotations[common.TransitPathAnnotation]; ok {
		vaultConfig.TransitPath = val
	} else {
		vaultConfig.TransitPath = viper.GetString("transit_path")
	}

	if val, ok := annotations[common.VaultAgentConfigmapAnnotation]; ok {
		vaultConfig.AgentConfigMap = val
	} else {
		vaultConfig.AgentConfigMap = ""
	}

	if val, ok := annotations[common.VaultAgentOnceAnnotation]; ok {
		vaultConfig.AgentOnce, _ = strconv.ParseBool(val)
	} else {
		vaultConfig.AgentOnce = false
	}

	// This is done to preserve backwards compatibility with vault-agent-cpu
	if val, err := resource.ParseQuantity(annotations[common.VaultAgentCPUAnnotation]); err == nil {
		vaultConfig.AgentCPULimit = val
	} else if val, err := resource.ParseQuantity(annotations[common.VaultAgentCPULimitAnnotation]); err == nil {
		vaultConfig.AgentCPULimit = val
	} else {
		vaultConfig.AgentCPULimit = resource.MustParse("100m")
	}

	// This is done to preserve backwards compatibility with vault-agent-memory
	if val, err := resource.ParseQuantity(annotations[common.VaultAgentMemoryAnnotation]); err == nil {
		vaultConfig.AgentMemoryLimit = val
	} else if val, err := resource.ParseQuantity(annotations[common.VaultAgentMemoryLimitAnnotation]); err == nil {
		vaultConfig.AgentMemoryLimit = val
	} else {
		vaultConfig.AgentMemoryLimit = resource.MustParse("128Mi")
	}

	if val, err := resource.ParseQuantity(annotations[common.VaultAgentCPURequestAnnotation]); err == nil {
		vaultConfig.AgentCPURequest = val
	} else {
		vaultConfig.AgentCPURequest = resource.MustParse("100m")
	}

	if val, err := resource.ParseQuantity(annotations[common.VaultAgentMemoryRequestAnnotation]); err == nil {
		vaultConfig.AgentMemoryRequest = val
	} else {
		vaultConfig.AgentMemoryRequest = resource.MustParse("128Mi")
	}

	if val, ok := annotations[common.VaultAgentShareProcessNamespaceAnnotation]; ok {
		vaultConfig.AgentShareProcessDefault = "found"
		vaultConfig.AgentShareProcess, _ = strconv.ParseBool(val)
	} else {
		vaultConfig.AgentShareProcessDefault = "empty"
		vaultConfig.AgentShareProcess = false
	}

	if val, ok := annotations[common.VaultFromPathAnnotation]; ok {
		vaultConfig.FromPath = val
	}

	if val, ok := annotations[common.TokenAuthMountAnnotation]; ok {
		vaultConfig.TokenAuthMount = val
	}

	if val, ok := annotations[common.VaultImageAnnotation]; ok {
		vaultConfig.AgentImage = val
	} else {
		vaultConfig.AgentImage = viper.GetString("vault_image")
	}
	if val, ok := annotations[common.VaultImagePullPolicyAnnotation]; ok {
		vaultConfig.AgentImagePullPolicy = getPullPolicy(val)
	} else {
		vaultConfig.AgentImagePullPolicy = getPullPolicy(viper.GetString("vault_image_pull_policy"))
	}

	if val, ok := annotations[common.VaultAgentEnvVariablesAnnotation]; ok {
		vaultConfig.AgentEnvVariables = val
	}

	if val, ok := annotations[common.VaultNamespaceAnnotation]; ok {
		vaultConfig.VaultNamespace = val
	} else {
		vaultConfig.VaultNamespace = viper.GetString("VAULT_NAMESPACE")
	}

	if val, ok := annotations[common.VaultConsuleTemplateInjectInInitcontainersAnnotation]; ok {
		vaultConfig.CtInjectInInitcontainers, _ = strconv.ParseBool(val)
	} else {
		vaultConfig.CtInjectInInitcontainers = false
	}

	if val, ok := annotations[common.TransitBatchSizeAnnotation]; ok {
		batchSize, _ := strconv.ParseInt(val, 10, 32)
		vaultConfig.TransitBatchSize = int(batchSize)
	} else {
		vaultConfig.TransitBatchSize = viper.GetInt("transit_batch_size")
	}

	vaultConfig.Token = viper.GetString("vault_token")

	return vaultConfig
}

func getPullPolicy(pullPolicyStr string) corev1.PullPolicy {
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

func SetConfigDefaults() {
	viper.SetDefault("vault_image", "hashicorp/vault:latest")
	viper.SetDefault("vault_image_pull_policy", string(corev1.PullIfNotPresent))
	viper.SetDefault("secret_init_image", "ghcr.io/bank-vaults/secret-init:latest")
	viper.SetDefault("secret_init_image_pull_policy", string(corev1.PullIfNotPresent))
	viper.SetDefault("vault_ct_image", "hashicorp/consul-template:0.32.0")
	viper.SetDefault("vault_ct_pull_policy", string(corev1.PullIfNotPresent))
	viper.SetDefault("vault_addr", "https://vault:8200")
	viper.SetDefault("vault_skip_verify", "false")
	viper.SetDefault("vault_path", "kubernetes")
	viper.SetDefault("vault_auth_method", "jwt")
	viper.SetDefault("vault_role", "")
	viper.SetDefault("vault_tls_secret", "")
	viper.SetDefault("vault_client_timeout", "10s")
	viper.SetDefault("vault_agent", "false")
	viper.SetDefault("secret_init_daemon", "false")
	viper.SetDefault("vault_ct_share_process_namespace", "")
	viper.SetDefault("psp_allow_privilege_escalation", "false")
	viper.SetDefault("run_as_non_root", "false")
	viper.SetDefault("run_as_user", "0")
	viper.SetDefault("run_as_group", "0")
	viper.SetDefault("readonly_root_fs", "false")
	viper.SetDefault("vault_ignore_missing_secrets", "false")
	viper.SetDefault("vault_passthrough", "")
	viper.SetDefault("mutate_configmap", "false")
	viper.SetDefault("tls_cert_file", "")
	viper.SetDefault("tls_private_key_file", "")
	viper.SetDefault("listen_address", ":8443")
	viper.SetDefault("telemetry_listen_address", "")
	viper.SetDefault("transit_key_id", "")
	viper.SetDefault("transit_path", "")
	viper.SetDefault("transit_batch_size", 25)
	viper.SetDefault("default_image_pull_secret", "")
	viper.SetDefault("default_image_pull_secret_service_account", "")
	viper.SetDefault("default_image_pull_secret_namespace", "")
	viper.SetDefault("registry_skip_verify", "false")
	viper.SetDefault("secret_init_json_log", "false")
	// Used by the webhook
	viper.SetDefault("log_level", "info")
	// Used by vault via secret-init
	viper.SetDefault("vault_log_level", "info")
	viper.SetDefault("vault_agent_share_process_namespace", "")
	viper.SetDefault("SECRET_INIT_CPU_REQUEST", "")
	viper.SetDefault("SECRET_INIT_MEMORY_REQUEST", "")
	viper.SetDefault("SECRET_INIT_CPU_LIMIT", "")
	viper.SetDefault("SECRET_INIT_MEMORY_LIMIT", "")
	viper.SetDefault("SECRET_INIT_LOG_SERVER", "")
	viper.SetDefault("SECRET_INIT_LOG_LEVEL", "info")
	viper.SetDefault("VAULT_NAMESPACE", "")

	viper.AutomaticEnv()
}
