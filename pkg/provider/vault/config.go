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
	"github.com/spf13/viper"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/bank-vaults/secrets-webhook/pkg/common"
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

func loadConfig(obj metav1.Object) (Config, error) {
	setDefaults()

	// This is done to preserve backwards compatibility with the deprecated environment variables
	handleDeprecatedEnvVars()

	config := Config{
		ObjectNamespace: obj.GetNamespace(),
	}

	annotations := obj.GetAnnotations()

	if val, ok := annotations[common.VaultAddrAnnotation]; ok {
		config.Addr = val
	} else if val, ok := annotations[common.VaultAddrAnnotationDeprecated]; ok {
		config.Addr = val
	} else {
		config.Addr = viper.GetString(common.VaultAddrEnvVar)
	}

	if val, ok := annotations[common.VaultRoleAnnotation]; ok {
		config.Role = val
	} else if val, ok := annotations[common.VaultRoleAnnotationDeprecated]; ok {
		config.Role = val
	} else {
		if val := viper.GetString(common.VaultRoleEnvVar); val != "" {
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
	} else if val, ok := annotations[common.VaultAuthMethodAnnotationDeprecated]; ok {
		config.AuthMethod = val
	} else {
		config.AuthMethod = viper.GetString(common.VaultAuthMethodEnvVar)
	}

	if val, ok := annotations[common.VaultPathAnnotation]; ok {
		config.Path = val
	} else if val, ok := annotations[common.VaultPathAnnotationDeprecated]; ok {
		config.Path = val
	} else {
		config.Path = viper.GetString(common.VaultPathEnvVar)
	}

	// TODO: Check for flag to verify we want to use namespace-local SAs instead of the webhook namespaces SA
	if val, ok := annotations[common.VaultServiceaccountAnnotation]; ok {
		config.VaultServiceAccount = val
	} else if val, ok := annotations[common.VaultServiceaccountAnnotationDeprecated]; ok {
		config.VaultServiceAccount = val
	} else {
		config.VaultServiceAccount = viper.GetString(common.VaultSAEnvVar)
	}

	if val, ok := annotations[common.VaultSkipVerifyAnnotation]; ok {
		config.SkipVerify, _ = strconv.ParseBool(val)
	} else if val, ok := annotations[common.VaultSkipVerifyAnnotationDeprecated]; ok {
		config.SkipVerify, _ = strconv.ParseBool(val)
	} else {
		config.SkipVerify = viper.GetBool(common.VaultSkipVerifyEnvVar)
	}

	if val, ok := annotations[common.VaultTLSSecretAnnotation]; ok {
		config.TLSSecret = val
	} else if val, ok := annotations[common.VaultTLSSecretAnnotationDeprecated]; ok {
		config.TLSSecret = val
	} else {
		config.TLSSecret = viper.GetString(common.VaultTLSSecretEnvVar)
	}

	if val, ok := annotations[common.VaultClientTimeoutAnnotation]; ok {
		config.ClientTimeout, _ = time.ParseDuration(val)
	} else if val, ok := annotations[common.VaultClientTimeoutAnnotationDeprecated]; ok {
		config.ClientTimeout, _ = time.ParseDuration(val)
	} else {
		config.ClientTimeout, _ = time.ParseDuration(viper.GetString(common.VaultClientTimeoutEnvVar))
	}

	if val, ok := annotations[common.VaultAgentAnnotation]; ok {
		config.UseAgent, _ = strconv.ParseBool(val)
	} else if val, ok := annotations[common.VaultAgentAnnotationDeprecated]; ok {
		config.UseAgent, _ = strconv.ParseBool(val)
	} else {
		config.UseAgent, _ = strconv.ParseBool(viper.GetString(common.VaultAgentEnvVar))
	}

	if val, ok := annotations[common.VaultConsulTemplateConfigmapAnnotation]; ok {
		config.CtConfigMap = val
	} else if val, ok := annotations[common.VaultConsulTemplateConfigmapAnnotationDeprecated]; ok {
		config.CtConfigMap = val
	} else {
		config.CtConfigMap = ""
	}

	if val, ok := annotations[common.VaultServiceAccountTokenVolumeNameAnnotation]; ok {
		config.ServiceAccountTokenVolumeName = val
	} else if val, ok := annotations[common.VaultServiceAccountTokenVolumeNameAnnotationDeprecated]; ok {
		config.ServiceAccountTokenVolumeName = val
	} else if val := viper.GetString(common.VaultSATokenVolumeNameEnvVar); val != "" {
		config.ServiceAccountTokenVolumeName = val
	} else {
		config.ServiceAccountTokenVolumeName = "/var/run/secrets/kubernetes.io/serviceaccount"
	}

	if val, ok := annotations[common.VaultConsulTemplateImageAnnotation]; ok {
		config.CtImage = val
	} else if val, ok := annotations[common.VaultConsulTemplateImageAnnotationDeprecated]; ok {
		config.CtImage = val
	} else {
		config.CtImage = viper.GetString(common.VaultCTImageEnvVar)
	}

	if val, ok := annotations[common.VaultIgnoreMissingSecretsAnnotation]; ok {
		config.IgnoreMissingSecrets = val
	} else if val, ok := annotations[common.VaultIgnoreMissingSecretsAnnotationDeprecated]; ok {
		config.IgnoreMissingSecrets = val
	} else {
		config.IgnoreMissingSecrets = viper.GetString(common.VaultIgnoreMissingSecretsEnvVar)
	}

	if val, ok := annotations[common.VaultPassthroughAnnotation]; ok {
		config.Passthrough = val
	} else if val, ok := annotations[common.VaultEnvPassthroughAnnotationDeprecated]; ok {
		config.Passthrough = val
	} else {
		config.Passthrough = viper.GetString(common.VaultPassthroughEnvVar)
	}

	if val, ok := annotations[common.VaultConfigfilePathAnnotation]; ok {
		config.ConfigfilePath = val
	} else if val, ok := annotations[common.VaultConfigfilePathAnnotationDeprecated]; ok {
		config.ConfigfilePath = val
	} else if val, ok := annotations[common.VaultConsulTemplateSecretsMountPathAnnotation]; ok {
		config.ConfigfilePath = val
	} else if val, ok := annotations[common.VaultConsulTemplateSecretsMountPathAnnotationDeprecated]; ok {
		config.ConfigfilePath = val
	} else {
		config.ConfigfilePath = "/vault/secrets"
	}

	if val, ok := annotations[common.VaultConsulTemplatePullPolicyAnnotation]; ok {
		config.CtImagePullPolicy = common.GetPullPolicy(val)
	} else if val, ok := annotations[common.VaultConsulTemplatePullPolicyAnnotationDeprecated]; ok {
		config.CtImagePullPolicy = common.GetPullPolicy(val)
	} else {
		config.CtImagePullPolicy = common.GetPullPolicy(viper.GetString(common.VaultCTPullPolicyEnvVar))
	}

	if val, ok := annotations[common.VaultConsulTemplateOnceAnnotation]; ok {
		config.CtOnce, _ = strconv.ParseBool(val)
	} else if val, ok := annotations[common.VaultConsulTemplateOnceAnnotationDeprecated]; ok {
		config.CtOnce, _ = strconv.ParseBool(val)
	} else {
		config.CtOnce = false
	}

	if val, err := resource.ParseQuantity(annotations[common.VaultConsulTemplateCPUAnnotation]); err == nil {
		config.CtCPU = val
	} else if val, err := resource.ParseQuantity(annotations[common.VaultConsulTemplateCPUAnnotationDeprecated]); err == nil {
		config.CtCPU = val
	} else {
		config.CtCPU = resource.MustParse("100m")
	}

	if val, err := resource.ParseQuantity(annotations[common.VaultConsulTemplateMemoryAnnotation]); err == nil {
		config.CtMemory = val
	} else if val, err := resource.ParseQuantity(annotations[common.VaultConsulTemplateMemoryAnnotationDeprecated]); err == nil {
		config.CtMemory = val
	} else {
		config.CtMemory = resource.MustParse("128Mi")
	}

	if val, ok := annotations[common.VaultConsulTemplateShareProcessNamespaceAnnotation]; ok {
		config.CtShareProcessDefault = "found"
		config.CtShareProcess, _ = strconv.ParseBool(val)
	} else if val, ok := annotations[common.VaultConsulTemplateShareProcessNamespaceAnnotationDeprecated]; ok {
		config.CtShareProcessDefault = "found"
		config.CtShareProcess, _ = strconv.ParseBool(val)
	} else {
		config.CtShareProcessDefault = "empty"
		config.CtShareProcess = false
	}

	if val, ok := annotations[common.VaultLogLevelAnnotation]; ok {
		config.LogLevel = val
	} else if val, ok := annotations[common.VaultLogLevelAnnotationDeprecated]; ok {
		config.LogLevel = val
	} else {
		config.LogLevel = viper.GetString(common.VaultLogLevelEnvVar)
	}

	if val, ok := annotations[common.VaultTransitKeyIDAnnotation]; ok {
		config.TransitKeyID = val
	} else if val, ok := annotations[common.VaultTransitKeyIDAnnotationDeprecated]; ok {
		config.TransitKeyID = val
	} else {
		config.TransitKeyID = viper.GetString(common.VaultTransitKeyIDEnvVar)
	}

	if val, ok := annotations[common.VaultTransitPathAnnotation]; ok {
		config.TransitPath = val
	} else if val, ok := annotations[common.VaultTransitPathAnnotationDeprecated]; ok {
		config.TransitPath = val
	} else {
		config.TransitPath = viper.GetString(common.VaultTransitPathEnvVar)
	}

	if val, ok := annotations[common.VaultAgentConfigmapAnnotation]; ok {
		config.AgentConfigMap = val
	} else if val, ok := annotations[common.VaultAgentConfigmapAnnotationDeprecated]; ok {
		config.AgentConfigMap = val
	} else {
		config.AgentConfigMap = ""
	}

	if val, ok := annotations[common.VaultAgentOnceAnnotation]; ok {
		config.AgentOnce, _ = strconv.ParseBool(val)
	} else if val, ok := annotations[common.VaultAgentOnceAnnotationDeprecated]; ok {
		config.AgentOnce, _ = strconv.ParseBool(val)
	} else {
		config.AgentOnce = false
	}

	// This is done to preserve backwards compatibility with vault-agent-cpu
	if val, err := resource.ParseQuantity(annotations[common.VaultAgentCPUAnnotation]); err == nil {
		config.AgentCPULimit = val
	} else if val, err := resource.ParseQuantity(annotations[common.VaultAgentCPUAnnotationDeprecated]); err == nil {
		config.AgentCPULimit = val
	} else if val, err := resource.ParseQuantity(annotations[common.VaultAgentCPULimitAnnotation]); err == nil {
		config.AgentCPULimit = val
	} else if val, err := resource.ParseQuantity(annotations[common.VaultAgentCPULimitAnnotationDeprecated]); err == nil {
		config.AgentCPULimit = val
	} else {
		config.AgentCPULimit = resource.MustParse("100m")
	}

	// This is done to preserve backwards compatibility with vault-agent-memory
	if val, err := resource.ParseQuantity(annotations[common.VaultAgentMemoryAnnotation]); err == nil {
		config.AgentMemoryLimit = val
	} else if val, err := resource.ParseQuantity(annotations[common.VaultAgentMemoryAnnotationDeprecated]); err == nil {
		config.AgentMemoryLimit = val
	} else if val, err := resource.ParseQuantity(annotations[common.VaultAgentMemoryLimitAnnotation]); err == nil {
		config.AgentMemoryLimit = val
	} else if val, err := resource.ParseQuantity(annotations[common.VaultAgentMemoryLimitAnnotationDeprecated]); err == nil {
		config.AgentMemoryLimit = val
	} else {
		config.AgentMemoryLimit = resource.MustParse("128Mi")
	}

	if val, err := resource.ParseQuantity(annotations[common.VaultAgentCPURequestAnnotation]); err == nil {
		config.AgentCPURequest = val
	} else if val, err := resource.ParseQuantity(annotations[common.VaultAgentCPURequestAnnotationDeprecated]); err == nil {
		config.AgentCPURequest = val
	} else {
		config.AgentCPURequest = resource.MustParse("100m")
	}

	if val, err := resource.ParseQuantity(annotations[common.VaultAgentMemoryRequestAnnotation]); err == nil {
		config.AgentMemoryRequest = val
	} else if val, err := resource.ParseQuantity(annotations[common.VaultAgentMemoryRequestAnnotationDeprecated]); err == nil {
		config.AgentMemoryRequest = val
	} else {
		config.AgentMemoryRequest = resource.MustParse("128Mi")
	}

	if val, ok := annotations[common.VaultAgentShareProcessNamespaceAnnotation]; ok {
		config.AgentShareProcessDefault = "found"
		config.AgentShareProcess, _ = strconv.ParseBool(val)
	} else if val, ok := annotations[common.VaultAgentShareProcessNamespaceAnnotationDeprecated]; ok {
		config.AgentShareProcessDefault = "found"
		config.AgentShareProcess, _ = strconv.ParseBool(val)
	} else {
		config.AgentShareProcessDefault = "empty"
		config.AgentShareProcess = false
	}

	if val, ok := annotations[common.VaultFromPathAnnotation]; ok {
		config.FromPath = val
	} else if val, ok := annotations[common.VaultEnvFromPathAnnotationDeprecated]; ok {
		config.FromPath = val
	}

	if val, ok := annotations[common.VaultTokenAuthMountAnnotation]; ok {
		config.TokenAuthMount = val
	} else if val, ok := annotations[common.VaultTokenAuthMountAnnotationDeprecated]; ok {
		config.TokenAuthMount = val
	}

	if val, ok := annotations[common.VaultImageAnnotation]; ok {
		config.AgentImage = val
	} else if val, ok := annotations[common.VaultImageAnnotationDeprecated]; ok {
		config.AgentImage = val
	} else {
		config.AgentImage = viper.GetString(common.VaultImageEnvVar)
	}

	if val, ok := annotations[common.VaultImagePullPolicyAnnotation]; ok {
		config.AgentImagePullPolicy = common.GetPullPolicy(val)
	} else if val, ok := annotations[common.VaultImagePullPolicyAnnotationDeprecated]; ok {
		config.AgentImagePullPolicy = common.GetPullPolicy(val)
	} else {
		config.AgentImagePullPolicy = common.GetPullPolicy(viper.GetString(common.VaultImagePullPolicyEnvVar))
	}

	if val, ok := annotations[common.VaultAgentEnvVariablesAnnotation]; ok {
		config.AgentEnvVariables = val
	} else if val, ok := annotations[common.VaultAgentEnvVariablesAnnotationDeprecated]; ok {
		config.AgentEnvVariables = val
	}

	if val, ok := annotations[common.VaultNamespaceAnnotation]; ok {
		config.VaultNamespace = val
	} else if val, ok := annotations[common.VaultNamespaceAnnotationDeprecated]; ok {
		config.VaultNamespace = val
	} else {
		config.VaultNamespace = viper.GetString(common.VaultNamespaceEnvVar)
	}

	if val, ok := annotations[common.VaultConsulTemplateInjectInInitcontainersAnnotation]; ok {
		config.CtInjectInInitcontainers, _ = strconv.ParseBool(val)
	} else if val, ok := annotations[common.VaultConsulTemplateInjectInInitcontainersAnnotationDeprecated]; ok {
		config.CtInjectInInitcontainers, _ = strconv.ParseBool(val)
	} else {
		config.CtInjectInInitcontainers = false
	}

	if val, ok := annotations[common.VaultTransitBatchSizeAnnotation]; ok {
		batchSize, _ := strconv.ParseInt(val, 10, 32)
		config.TransitBatchSize = int(batchSize)
	} else if val, ok := annotations[common.VaultTransitBatchSizeAnnotationDeprecated]; ok {
		batchSize, _ := strconv.ParseInt(val, 10, 32)
		config.TransitBatchSize = int(batchSize)
	} else {
		config.TransitBatchSize = viper.GetInt(common.VaultTransitBatchSizeEnvVar)
	}

	config.Token = viper.GetString(common.VaultTokenEnvVar)

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

func setDefaults() {
	viper.SetDefault(common.VaultImageEnvVar, "hashicorp/vault:latest")
	viper.SetDefault(common.VaultImagePullPolicyEnvVar, string(corev1.PullIfNotPresent))
	viper.SetDefault(common.VaultCTImageEnvVar, "hashicorp/consul-template:0.32.0")
	viper.SetDefault(common.VaultCTPullPolicyEnvVar, string(corev1.PullIfNotPresent))
	viper.SetDefault(common.VaultAddrEnvVar, "https://vault:8200")
	viper.SetDefault(common.VaultSkipVerifyEnvVar, "false")
	viper.SetDefault(common.VaultPathEnvVar, "kubernetes")
	viper.SetDefault(common.VaultAuthMethodEnvVar, "jwt")
	viper.SetDefault(common.VaultRoleEnvVar, "")
	viper.SetDefault(common.VaultTLSSecretEnvVar, "")
	viper.SetDefault(common.VaultClientTimeoutEnvVar, "10s")
	viper.SetDefault(common.VaultAgentEnvVar, "false")
	viper.SetDefault(common.VaultCTShareProcessNamespaceEnvVar, "")
	viper.SetDefault(common.VaultIgnoreMissingSecretsEnvVar, "false")
	viper.SetDefault(common.VaultPassthroughEnvVar, "")
	viper.SetDefault(common.VaultAgentShareProcessNamespaceEnvVar, "")
	viper.SetDefault(common.VaultLogLevelEnvVar, "info")
	viper.SetDefault(common.VaultNamespaceEnvVar, "")
	viper.SetDefault(common.VaultTransitKeyIDEnvVar, "")
	viper.SetDefault(common.VaultTransitPathEnvVar, "")
	viper.SetDefault(common.VaultTransitBatchSizeEnvVar, 25)

	viper.AutomaticEnv()
}

// This is implemented to preserve backwards compatibility with the deprecated environment variables
func handleDeprecatedEnvVars() {
	if val := viper.GetString(common.VaultSATokenVolumeNameEnvVarDeprecated); val != "" {
		viper.Set(common.VaultSATokenVolumeNameEnvVar, val)
	}

	if val := viper.GetString(common.VaultTransitKeyIDEnvVarDeprecated); val != "" {
		viper.Set(common.VaultTransitKeyIDEnvVar, val)
	}

	if val := viper.GetString(common.VaultTransitPathEnvVarDeprecated); val != "" {
		viper.Set(common.VaultTransitPathEnvVar, val)
	}

	if val := viper.GetInt(common.VaultTransitBatchSizeEnvVarDeprecated); val != 0 {
		viper.Set(common.VaultTransitBatchSizeEnvVar, val)
	}

	if val := viper.GetString(common.VaultNamespaceEnvVarDeprecated); val != "" {
		viper.Set(common.VaultNamespaceEnvVar, val)
	}

	if val := viper.GetString(common.VaultEnvPassthroughEnvVarDeprecated); val != "" {
		viper.Set(common.VaultPassthroughEnvVar, val)
	}
}
