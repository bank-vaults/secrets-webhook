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

func LoadConfig(obj metav1.Object, namespace string) (Config, error) {
	SetDefaults()

	config := Config{
		ObjectNamespace: namespace,
	}

	// Preserve backwards compatibility with deprecated environment variables and annotations
	handleDeprecatedEnvVars()
	annotations := handleDeprecatedAnnotations(obj.GetAnnotations())

	if val, ok := annotations[common.VaultAddrAnnotation]; ok {
		config.Addr = val
	} else {
		config.Addr = viper.GetString(common.VaultAddrEnvVar)
	}

	if val, ok := annotations[common.VaultRoleAnnotation]; ok {
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
	} else {
		config.AuthMethod = viper.GetString(common.VaultAuthMethodEnvVar)
	}

	if val, ok := annotations[common.VaultPathAnnotation]; ok {
		config.Path = val
	} else {
		config.Path = viper.GetString(common.VaultPathEnvVar)
	}

	// TODO: Check for flag to verify we want to use namespace-local SAs instead of the webhook namespaces SA
	if val, ok := annotations[common.VaultServiceaccountAnnotation]; ok {
		config.VaultServiceAccount = val
	} else {
		config.VaultServiceAccount = viper.GetString(common.VaultSAEnvVar)
	}

	if val, ok := annotations[common.VaultSkipVerifyAnnotation]; ok {
		config.SkipVerify, _ = strconv.ParseBool(val)
	} else {
		config.SkipVerify = viper.GetBool(common.VaultSkipVerifyEnvVar)
	}

	if val, ok := annotations[common.VaultTLSSecretAnnotation]; ok {
		config.TLSSecret = val
	} else {
		config.TLSSecret = viper.GetString(common.VaultTLSSecretEnvVar)
	}

	if val, ok := annotations[common.VaultClientTimeoutAnnotation]; ok {
		config.ClientTimeout, _ = time.ParseDuration(val)
	} else {
		config.ClientTimeout, _ = time.ParseDuration(viper.GetString(common.VaultClientTimeoutEnvVar))
	}

	if val, ok := annotations[common.VaultAgentAnnotation]; ok {
		config.UseAgent, _ = strconv.ParseBool(val)
	} else {
		config.UseAgent, _ = strconv.ParseBool(viper.GetString(common.VaultAgentEnvVar))
	}

	if val, ok := annotations[common.VaultConsulTemplateConfigmapAnnotation]; ok {
		config.CtConfigMap = val
	} else {
		config.CtConfigMap = ""
	}

	if val, ok := annotations[common.VaultServiceAccountTokenVolumeNameAnnotation]; ok {
		config.ServiceAccountTokenVolumeName = val
	} else if viper.GetString(common.VaultSATokenVolumeNameEnvVar) != "" {
		config.ServiceAccountTokenVolumeName = viper.GetString(common.VaultSATokenVolumeNameEnvVar)
	} else {
		config.ServiceAccountTokenVolumeName = "/var/run/secrets/kubernetes.io/serviceaccount"
	}

	if val, ok := annotations[common.VaultConsulTemplateImageAnnotation]; ok {
		config.CtImage = val
	} else {
		config.CtImage = viper.GetString(common.VaultCTImageEnvVar)
	}

	if val, ok := annotations[common.VaultIgnoreMissingSecretsAnnotation]; ok {
		config.IgnoreMissingSecrets = val
	} else {
		config.IgnoreMissingSecrets = viper.GetString(common.VaultIgnoreMissingSecretsEnvVar)
	}

	if val, ok := annotations[common.VaultPassthroughAnnotation]; ok {
		config.Passthrough = val
	} else {
		config.Passthrough = viper.GetString(common.VaultPassthroughEnvVar)
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
		config.CtImagePullPolicy = common.GetPullPolicy(viper.GetString(common.VaultCTPullPolicyEnvVar))
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

	if val, ok := annotations[common.VaultLogLevelAnnotation]; ok {
		config.LogLevel = val
	} else {
		config.LogLevel = viper.GetString(common.VaultLogLevelEnvVar)
	}

	if val, ok := annotations[common.VaultTransitKeyIDAnnotation]; ok {
		config.TransitKeyID = val
	} else {
		config.TransitKeyID = viper.GetString(common.VaultTransitKeyIDEnvVar)
	}

	if val, ok := annotations[common.VaultTransitPathAnnotation]; ok {
		config.TransitPath = val
	} else {
		config.TransitPath = viper.GetString(common.VaultTransitPathEnvVar)
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

	if val, ok := annotations[common.VaultTokenAuthMountAnnotation]; ok {
		config.TokenAuthMount = val
	}

	if val, ok := annotations[common.VaultImageAnnotation]; ok {
		config.AgentImage = val
	} else {
		config.AgentImage = viper.GetString(common.VaultImageEnvVar)
	}
	if val, ok := annotations[common.VaultImagePullPolicyAnnotation]; ok {
		config.AgentImagePullPolicy = common.GetPullPolicy(val)
	} else {
		config.AgentImagePullPolicy = common.GetPullPolicy(viper.GetString(common.VaultImagePullPolicyEnvVar))
	}

	if val, ok := annotations[common.VaultAgentEnvVariablesAnnotation]; ok {
		config.AgentEnvVariables = val
	}

	if val, ok := annotations[common.VaultNamespaceAnnotation]; ok {
		config.VaultNamespace = val
	} else {
		config.VaultNamespace = viper.GetString(common.VaultNamespaceEnvVar)
	}

	if val, ok := annotations[common.VaultConsulTemplateInjectInInitcontainersAnnotation]; ok {
		config.CtInjectInInitcontainers, _ = strconv.ParseBool(val)
	} else {
		config.CtInjectInInitcontainers = false
	}

	if val, ok := annotations[common.VaultTransitBatchSizeAnnotation]; ok {
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

func SetDefaults() {
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

// This is implemented to preserve backwards compatibility with the deprecated annotations
func handleDeprecatedAnnotations(annotations map[string]string) map[string]string {
	if val, ok := annotations[common.VaultAddrAnnotationDeprecated]; ok {
		annotations[common.VaultAddrAnnotation] = val
		delete(annotations, common.VaultAddrAnnotationDeprecated)
	}

	if val, ok := annotations[common.VaultRoleAnnotationDeprecated]; ok {
		annotations[common.VaultRoleAnnotation] = val
		delete(annotations, common.VaultRoleAnnotationDeprecated)
	}

	if val, ok := annotations[common.VaultAuthMethodAnnotationDeprecated]; ok {
		annotations[common.VaultAuthMethodAnnotation] = val
		delete(annotations, common.VaultAuthMethodAnnotationDeprecated)
	}

	if val, ok := annotations[common.VaultPathAnnotationDeprecated]; ok {
		annotations[common.VaultPathAnnotation] = val
		delete(annotations, common.VaultPathAnnotationDeprecated)
	}

	if val, ok := annotations[common.VaultServiceaccountAnnotationDeprecated]; ok {
		annotations[common.VaultServiceaccountAnnotation] = val
		delete(annotations, common.VaultServiceaccountAnnotationDeprecated)
	}

	if val, ok := annotations[common.VaultSkipVerifyAnnotationDeprecated]; ok {
		annotations[common.VaultSkipVerifyAnnotation] = val
		delete(annotations, common.VaultSkipVerifyAnnotationDeprecated)
	}

	if val, ok := annotations[common.VaultTLSSecretAnnotationDeprecated]; ok {
		annotations[common.VaultTLSSecretAnnotation] = val
		delete(annotations, common.VaultTLSSecretAnnotationDeprecated)
	}

	if val, ok := annotations[common.VaultClientTimeoutAnnotationDeprecated]; ok {
		annotations[common.VaultClientTimeoutAnnotation] = val
		delete(annotations, common.VaultClientTimeoutAnnotationDeprecated)
	}

	if val, ok := annotations[common.VaultAgentAnnotationDeprecated]; ok {
		annotations[common.VaultAgentAnnotation] = val
		delete(annotations, common.VaultAgentAnnotationDeprecated)
	}

	if val, ok := annotations[common.VaultConsulTemplateConfigmapAnnotationDeprecated]; ok {
		annotations[common.VaultConsulTemplateConfigmapAnnotation] = val
		delete(annotations, common.VaultConsulTemplateConfigmapAnnotationDeprecated)
	}

	if val, ok := annotations[common.VaultServiceAccountTokenVolumeNameAnnotationDeprecated]; ok {
		annotations[common.VaultServiceAccountTokenVolumeNameAnnotation] = val
		delete(annotations, common.VaultServiceAccountTokenVolumeNameAnnotationDeprecated)
	}

	if val, ok := annotations[common.VaultConsulTemplateImageAnnotationDeprecated]; ok {
		annotations[common.VaultConsulTemplateImageAnnotation] = val
		delete(annotations, common.VaultConsulTemplateImageAnnotationDeprecated)
	}

	if val, ok := annotations[common.VaultIgnoreMissingSecretsAnnotationDeprecated]; ok {
		annotations[common.VaultIgnoreMissingSecretsAnnotation] = val
		delete(annotations, common.VaultIgnoreMissingSecretsAnnotationDeprecated)
	}

	if val, ok := annotations[common.VaultEnvPassthroughAnnotationDeprecated]; ok {
		annotations[common.VaultPassthroughAnnotation] = val
		delete(annotations, common.VaultEnvPassthroughAnnotationDeprecated)
	}

	if val, ok := annotations[common.VaultConfigfilePathAnnotationDeprecated]; ok {
		annotations[common.VaultConfigfilePathAnnotation] = val
		delete(annotations, common.VaultConfigfilePathAnnotationDeprecated)
	}

	if val, ok := annotations[common.VaultConsulTemplateSecretsMountPathAnnotationDeprecated]; ok {
		annotations[common.VaultConsulTemplateSecretsMountPathAnnotation] = val
		delete(annotations, common.VaultConsulTemplateSecretsMountPathAnnotationDeprecated)
	}

	if val, ok := annotations[common.VaultConsulTemplatePullPolicyAnnotationDeprecated]; ok {
		annotations[common.VaultConsulTemplatePullPolicyAnnotation] = val
		delete(annotations, common.VaultConsulTemplatePullPolicyAnnotationDeprecated)
	}

	if val, ok := annotations[common.VaultConsulTemplateOnceAnnotationDeprecated]; ok {
		annotations[common.VaultConsulTemplateOnceAnnotation] = val
		delete(annotations, common.VaultConsulTemplateOnceAnnotationDeprecated)
	}

	if val, ok := annotations[common.VaultConsulTemplateCPUAnnotationDeprecated]; ok {
		annotations[common.VaultConsulTemplateCPUAnnotation] = val
		delete(annotations, common.VaultConsulTemplateCPUAnnotationDeprecated)
	}

	if val, ok := annotations[common.VaultConsulTemplateMemoryAnnotationDeprecated]; ok {
		annotations[common.VaultConsulTemplateMemoryAnnotation] = val
		delete(annotations, common.VaultConsulTemplateMemoryAnnotationDeprecated)
	}

	if val, ok := annotations[common.VaultConsulTemplateShareProcessNamespaceAnnotationDeprecated]; ok {
		annotations[common.VaultConsulTemplateShareProcessNamespaceAnnotation] = val
		delete(annotations, common.VaultConsulTemplateShareProcessNamespaceAnnotationDeprecated)
	}

	if val, ok := annotations[common.VaultLogLevelAnnotationDeprecated]; ok {
		annotations[common.VaultLogLevelAnnotation] = val
		delete(annotations, common.VaultLogLevelAnnotationDeprecated)
	}

	if val, ok := annotations[common.VaultTransitKeyIDAnnotationDeprecated]; ok {
		annotations[common.VaultTransitKeyIDAnnotation] = val
		delete(annotations, common.VaultTransitKeyIDAnnotationDeprecated)
	}

	if val, ok := annotations[common.VaultTransitPathAnnotationDeprecated]; ok {
		annotations[common.VaultTransitPathAnnotation] = val
		delete(annotations, common.VaultTransitPathAnnotationDeprecated)
	}

	if val, ok := annotations[common.VaultAgentConfigmapAnnotationDeprecated]; ok {
		annotations[common.VaultAgentConfigmapAnnotation] = val
		delete(annotations, common.VaultAgentConfigmapAnnotationDeprecated)
	}

	if val, ok := annotations[common.VaultAgentOnceAnnotationDeprecated]; ok {
		annotations[common.VaultAgentOnceAnnotation] = val
		delete(annotations, common.VaultAgentOnceAnnotationDeprecated)
	}

	if val, ok := annotations[common.VaultAgentCPUAnnotationDeprecated]; ok {
		annotations[common.VaultAgentCPUAnnotation] = val
		delete(annotations, common.VaultAgentCPUAnnotationDeprecated)
	}

	if val, ok := annotations[common.VaultAgentCPULimitAnnotationDeprecated]; ok {
		annotations[common.VaultAgentCPULimitAnnotation] = val
		delete(annotations, common.VaultAgentCPULimitAnnotationDeprecated)
	}

	if val, ok := annotations[common.VaultAgentMemoryAnnotationDeprecated]; ok {
		annotations[common.VaultAgentMemoryAnnotation] = val
		delete(annotations, common.VaultAgentMemoryAnnotationDeprecated)
	}

	if val, ok := annotations[common.VaultAgentMemoryLimitAnnotationDeprecated]; ok {
		annotations[common.VaultAgentMemoryLimitAnnotation] = val
		delete(annotations, common.VaultAgentMemoryLimitAnnotationDeprecated)
	}

	if val, ok := annotations[common.VaultAgentCPURequestAnnotationDeprecated]; ok {
		annotations[common.VaultAgentCPURequestAnnotation] = val
		delete(annotations, common.VaultAgentCPURequestAnnotationDeprecated)
	}

	if val, ok := annotations[common.VaultAgentMemoryRequestAnnotationDeprecated]; ok {
		annotations[common.VaultAgentMemoryRequestAnnotation] = val
		delete(annotations, common.VaultAgentMemoryRequestAnnotationDeprecated)
	}

	if val, ok := annotations[common.VaultAgentShareProcessNamespaceAnnotationDeprecated]; ok {
		annotations[common.VaultAgentShareProcessNamespaceAnnotation] = val
		delete(annotations, common.VaultAgentShareProcessNamespaceAnnotationDeprecated)
	}

	if val, ok := annotations[common.VaultEnvFromPathAnnotationDeprecated]; ok {
		annotations[common.VaultFromPathAnnotation] = val
		delete(annotations, common.VaultEnvFromPathAnnotationDeprecated)
	}

	if val, ok := annotations[common.VaultTokenAuthMountAnnotationDeprecated]; ok {
		annotations[common.VaultTokenAuthMountAnnotation] = val
		delete(annotations, common.VaultTokenAuthMountAnnotationDeprecated)
	}

	if val, ok := annotations[common.VaultImageAnnotationDeprecated]; ok {
		annotations[common.VaultImageAnnotation] = val
		delete(annotations, common.VaultImageAnnotationDeprecated)
	}

	if val, ok := annotations[common.VaultImagePullPolicyAnnotationDeprecated]; ok {
		annotations[common.VaultImagePullPolicyAnnotation] = val
		delete(annotations, common.VaultImagePullPolicyAnnotationDeprecated)
	}

	if val, ok := annotations[common.VaultAgentEnvVariablesAnnotationDeprecated]; ok {
		annotations[common.VaultAgentEnvVariablesAnnotation] = val
		delete(annotations, common.VaultAgentEnvVariablesAnnotationDeprecated)
	}

	if val, ok := annotations[common.VaultNamespaceAnnotationDeprecated]; ok {
		annotations[common.VaultNamespaceAnnotation] = val
		delete(annotations, common.VaultNamespaceAnnotationDeprecated)
	}

	if val, ok := annotations[common.VaultConsulTemplateInjectInInitcontainersAnnotationDeprecated]; ok {
		annotations[common.VaultConsulTemplateInjectInInitcontainersAnnotation] = val
		delete(annotations, common.VaultConsulTemplateInjectInInitcontainersAnnotationDeprecated)
	}

	if val, ok := annotations[common.VaultTransitBatchSizeAnnotationDeprecated]; ok {
		annotations[common.VaultTransitBatchSizeAnnotation] = val
		delete(annotations, common.VaultTransitBatchSizeAnnotationDeprecated)
	}

	return annotations
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
