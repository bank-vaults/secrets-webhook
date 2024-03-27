// Copyright © 2023 Bank-Vaults Maintainers
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
	"fmt"
	"html/template"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"emperror.dev/errors"
	"github.com/slok/kubewebhook/v2/pkg/model"
	"github.com/spf13/viper"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/bank-vaults/secrets-webhook/pkg/common"
)

const (
	AgentConfig = `
pid_file = "/tmp/pidfile"

auto_auth {
        method "kubernetes" {
                namespace = "%s"
                mount_path = "auth/%s"
                config = {
                        role = "%s"
                }
        }

        sink "file" {
                config = {
                        path = "/vault/.vault-token"
                }
        }
}`
	ProviderName = "vault"
)

type Config struct {
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

func ParseConfig(obj metav1.Object, ar *model.AdmissionReview) (Config, error) {
	SetDefaults()

	config := Config{
		ObjectNamespace: ar.Namespace,
	}

	annotations := obj.GetAnnotations()

	if val, ok := annotations[common.VaultAddrAnnotation]; ok {
		config.Addr = val
	} else {
		config.Addr = viper.GetString("vault_addr")
	}

	if val, ok := annotations[common.VaultRoleAnnotation]; ok {
		config.Role = val
	} else {
		if val := viper.GetString("vault_role"); val != "" {
			config.Role = val
		} else {
			switch p := obj.(type) {
			case *corev1.Pod:
				config.Role = p.Spec.ServiceAccountName
			default:
				config.Role = "default"
			}
		}
	}

	if val, ok := annotations[common.VaultAuthMethodAnnotation]; ok {
		config.AuthMethod = val
	} else {
		config.AuthMethod = viper.GetString("vault_auth_method")
	}

	if val, ok := annotations[common.VaultPathAnnotation]; ok {
		config.Path = val
	} else {
		config.Path = viper.GetString("vault_path")
	}

	// TODO: Check for flag to verify we want to use namespace-local SAs instead of the webhook namespaces SA
	if val, ok := annotations[common.VaultServiceaccountAnnotation]; ok {
		config.VaultServiceAccount = val
	} else {
		config.VaultServiceAccount = viper.GetString("vault_serviceaccount")
	}

	if val, ok := annotations[common.VaultSkipVerifyAnnotation]; ok {
		config.SkipVerify, _ = strconv.ParseBool(val)
	} else {
		config.SkipVerify = viper.GetBool("vault_skip_verify")
	}

	if val, ok := annotations[common.VaultTLSSecretAnnotation]; ok {
		config.TLSSecret = val
	} else {
		config.TLSSecret = viper.GetString("vault_tls_secret")
	}

	if val, ok := annotations[common.VaultClientTimeoutAnnotation]; ok {
		config.ClientTimeout, _ = time.ParseDuration(val)
	} else {
		config.ClientTimeout, _ = time.ParseDuration(viper.GetString("vault_client_timeout"))
	}

	if val, ok := annotations[common.VaultAgentAnnotation]; ok {
		config.UseAgent, _ = strconv.ParseBool(val)
	} else {
		config.UseAgent, _ = strconv.ParseBool(viper.GetString("vault_agent"))
	}

	if val, ok := annotations[common.VaultConsulTemplateConfigmapAnnotation]; ok {
		config.CtConfigMap = val
	} else {
		config.CtConfigMap = ""
	}

	if val, ok := annotations[common.ServiceAccountTokenVolumeNameAnnotation]; ok {
		config.ServiceAccountTokenVolumeName = val
	} else if viper.GetString("SERVICE_ACCOUNT_TOKEN_VOLUME_NAME") != "" {
		config.ServiceAccountTokenVolumeName = viper.GetString("SERVICE_ACCOUNT_TOKEN_VOLUME_NAME")
	} else {
		config.ServiceAccountTokenVolumeName = "/var/run/secrets/kubernetes.io/serviceaccount"
	}

	if val, ok := annotations[common.VaultConsulTemplateImageAnnotation]; ok {
		config.CtImage = val
	} else {
		config.CtImage = viper.GetString("vault_ct_image")
	}

	if val, ok := annotations[common.VaultIgnoreMissingSecretsAnnotation]; ok {
		config.IgnoreMissingSecrets = val
	} else {
		config.IgnoreMissingSecrets = viper.GetString("vault_ignore_missing_secrets")
	}

	if val, ok := annotations[common.VaultPassthroughAnnotation]; ok {
		config.Passthrough = val
	} else {
		config.Passthrough = viper.GetString("vault_passthrough")
	}

	if val, ok := annotations[common.VaultConfigfilePathAnnotation]; ok {
		config.ConfigfilePath = val
	} else if val, ok := annotations[common.VaultConsulTemplateSecretsMountPathAnnotation]; ok {
		config.ConfigfilePath = val
	} else {
		config.ConfigfilePath = "/vault/secrets"
	}

	if val, ok := annotations[common.VaultConsulTemplatePullPolicyAnnotation]; ok {
		config.CtImagePullPolicy = common.GetPullPolicy(val)
	} else {
		config.CtImagePullPolicy = common.GetPullPolicy(viper.GetString("vault_ct_pull_policy"))
	}

	if val, ok := annotations[common.VaultConsulTemplateOnceAnnotation]; ok {
		config.CtOnce, _ = strconv.ParseBool(val)
	} else {
		config.CtOnce = false
	}

	if val, err := resource.ParseQuantity(annotations[common.VaultConsulTemplateCPUAnnotation]); err == nil {
		config.CtCPU = val
	} else {
		config.CtCPU = resource.MustParse("100m")
	}

	if val, err := resource.ParseQuantity(annotations[common.VaultConsulTemplateMemoryAnnotation]); err == nil {
		config.CtMemory = val
	} else {
		config.CtMemory = resource.MustParse("128Mi")
	}

	if val, ok := annotations[common.VaultConsulTemplateShareProcessNamespaceAnnotation]; ok {
		config.CtShareProcessDefault = "found"
		config.CtShareProcess, _ = strconv.ParseBool(val)
	} else {
		config.CtShareProcessDefault = "empty"
		config.CtShareProcess = false
	}

	if val, ok := annotations[common.LogLevelAnnotation]; ok {
		config.LogLevel = val
	} else {
		config.LogLevel = viper.GetString("vault_log_level")
	}

	if val, ok := annotations[common.TransitKeyIDAnnotation]; ok {
		config.TransitKeyID = val
	} else {
		config.TransitKeyID = viper.GetString("transit_key_id")
	}

	if val, ok := annotations[common.TransitPathAnnotation]; ok {
		config.TransitPath = val
	} else {
		config.TransitPath = viper.GetString("transit_path")
	}

	if val, ok := annotations[common.VaultAgentConfigmapAnnotation]; ok {
		config.AgentConfigMap = val
	} else {
		config.AgentConfigMap = ""
	}

	if val, ok := annotations[common.VaultAgentOnceAnnotation]; ok {
		config.AgentOnce, _ = strconv.ParseBool(val)
	} else {
		config.AgentOnce = false
	}

	// This is done to preserve backwards compatibility with vault-agent-cpu
	if val, err := resource.ParseQuantity(annotations[common.VaultAgentCPUAnnotation]); err == nil {
		config.AgentCPULimit = val
	} else if val, err := resource.ParseQuantity(annotations[common.VaultAgentCPULimitAnnotation]); err == nil {
		config.AgentCPULimit = val
	} else {
		config.AgentCPULimit = resource.MustParse("100m")
	}

	// This is done to preserve backwards compatibility with vault-agent-memory
	if val, err := resource.ParseQuantity(annotations[common.VaultAgentMemoryAnnotation]); err == nil {
		config.AgentMemoryLimit = val
	} else if val, err := resource.ParseQuantity(annotations[common.VaultAgentMemoryLimitAnnotation]); err == nil {
		config.AgentMemoryLimit = val
	} else {
		config.AgentMemoryLimit = resource.MustParse("128Mi")
	}

	if val, err := resource.ParseQuantity(annotations[common.VaultAgentCPURequestAnnotation]); err == nil {
		config.AgentCPURequest = val
	} else {
		config.AgentCPURequest = resource.MustParse("100m")
	}

	if val, err := resource.ParseQuantity(annotations[common.VaultAgentMemoryRequestAnnotation]); err == nil {
		config.AgentMemoryRequest = val
	} else {
		config.AgentMemoryRequest = resource.MustParse("128Mi")
	}

	if val, ok := annotations[common.VaultAgentShareProcessNamespaceAnnotation]; ok {
		config.AgentShareProcessDefault = "found"
		config.AgentShareProcess, _ = strconv.ParseBool(val)
	} else {
		config.AgentShareProcessDefault = "empty"
		config.AgentShareProcess = false
	}

	if val, ok := annotations[common.VaultFromPathAnnotation]; ok {
		config.FromPath = val
	}

	if val, ok := annotations[common.TokenAuthMountAnnotation]; ok {
		config.TokenAuthMount = val
	}

	if val, ok := annotations[common.VaultImageAnnotation]; ok {
		config.AgentImage = val
	} else {
		config.AgentImage = viper.GetString("vault_image")
	}
	if val, ok := annotations[common.VaultImagePullPolicyAnnotation]; ok {
		config.AgentImagePullPolicy = common.GetPullPolicy(val)
	} else {
		config.AgentImagePullPolicy = common.GetPullPolicy(viper.GetString("vault_image_pull_policy"))
	}

	if val, ok := annotations[common.VaultAgentEnvVariablesAnnotation]; ok {
		config.AgentEnvVariables = val
	}

	if val, ok := annotations[common.VaultNamespaceAnnotation]; ok {
		config.VaultNamespace = val
	} else {
		config.VaultNamespace = viper.GetString("VAULT_NAMESPACE")
	}

	if val, ok := annotations[common.VaultConsulTemplateInjectInInitcontainersAnnotation]; ok {
		config.CtInjectInInitcontainers, _ = strconv.ParseBool(val)
	} else {
		config.CtInjectInInitcontainers = false
	}

	if val, ok := annotations[common.TransitBatchSizeAnnotation]; ok {
		batchSize, _ := strconv.ParseInt(val, 10, 32)
		config.TransitBatchSize = int(batchSize)
	} else {
		config.TransitBatchSize = viper.GetInt("transit_batch_size")
	}

	config.Token = viper.GetString("vault_token")

	// parse resulting config.Role as potential template with fields of config
	tmpl, err := template.New("vaultRole").Option("missingkey=error").Parse(config.Role)
	if err != nil {
		return Config{}, errors.Wrap(err, "error parsing vault_role")
	}

	var vRoleBuf strings.Builder
	if err = tmpl.Execute(&vRoleBuf, map[string]string{
		"authmethod":     config.AuthMethod,
		"name":           obj.GetName(),
		"namespace":      config.ObjectNamespace,
		"path":           config.Path,
		"serviceaccount": config.VaultServiceAccount,
	}); err != nil {
		return Config{}, errors.Wrap(err, "error templating vault_role")
	}

	config.Role = vRoleBuf.String()
	slog.Debug(fmt.Sprintf("config.Role = '%s'", config.Role))

	return config, nil
}

func SetDefaults() {
	viper.SetDefault("vault_image", "hashicorp/vault:latest")
	viper.SetDefault("vault_image_pull_policy", string(corev1.PullIfNotPresent))
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
	viper.SetDefault("vault_ct_share_process_namespace", "")
	viper.SetDefault("vault_ignore_missing_secrets", "false")
	viper.SetDefault("vault_passthrough", "")
	viper.SetDefault("vault_agent_share_process_namespace", "")
	viper.SetDefault("vault_log_level", "info")
	viper.SetDefault("VAULT_NAMESPACE", "")
	viper.SetDefault("transit_key_id", "")
	viper.SetDefault("transit_path", "")
	viper.SetDefault("transit_batch_size", 25)
	viper.AutomaticEnv()
}
