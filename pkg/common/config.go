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
	"strconv"
	"time"

	"github.com/spf13/viper"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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
	Provider                    string
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

func LoadWebhookConfig(obj metav1.Object) Config {
	config := Config{}

	handleDeprecatedEnvVars()
	annotations := handleDeprecatedAnnotations(obj.GetAnnotations())

	if val := annotations[MutateAnnotation]; val == "skip" {
		config.Mutate = true

		return config
	}

	if val, ok := annotations[PSPAllowPrivilegeEscalationAnnotation]; ok {
		config.PspAllowPrivilegeEscalation, _ = strconv.ParseBool(val)
	} else {
		config.PspAllowPrivilegeEscalation, _ = strconv.ParseBool(viper.GetString(PSPAllowPrivilegeEscalationEnvVar))
	}

	if val, ok := annotations[RunAsNonRootAnnotation]; ok {
		config.RunAsNonRoot, _ = strconv.ParseBool(val)
	} else {
		config.RunAsNonRoot, _ = strconv.ParseBool(viper.GetString(RunAsNonRootEnvVar))
	}

	if val, ok := annotations[RunAsUserAnnotation]; ok {
		config.RunAsUser, _ = strconv.ParseInt(val, 10, 64)
	} else {
		config.RunAsUser, _ = strconv.ParseInt(viper.GetString(RunAsUserEnvVar), 0, 64)
	}

	if val, ok := annotations[RunAsGroupAnnotation]; ok {
		config.RunAsGroup, _ = strconv.ParseInt(val, 10, 64)
	} else {
		config.RunAsGroup, _ = strconv.ParseInt(viper.GetString(RunAsGroupEnvVar), 0, 64)
	}

	if val, ok := annotations[ReadOnlyRootFsAnnotation]; ok {
		config.ReadOnlyRootFilesystem, _ = strconv.ParseBool(val)
	} else {
		config.ReadOnlyRootFilesystem, _ = strconv.ParseBool(viper.GetString(ReadonlyRootFSEnvVar))
	}

	if val, ok := annotations[RegistrySkipVerifyAnnotation]; ok {
		config.RegistrySkipVerify, _ = strconv.ParseBool(val)
	} else {
		config.RegistrySkipVerify, _ = strconv.ParseBool(viper.GetString(RegistrySkipVerifyEnvVar))
	}

	if val, ok := annotations[MutateProbesAnnotation]; ok {
		config.MutateProbes, _ = strconv.ParseBool(val)
	}

	if val, ok := annotations[ProviderAnnotation]; ok {
		config.Provider = val
	}

	return config
}

func LoadSecretInitConfig(obj metav1.Object) SecretInitConfig {
	secretInitConfig := SecretInitConfig{}

	annotations := obj.GetAnnotations()

	if val, ok := annotations[SecretInitDaemonAnnotation]; ok {
		secretInitConfig.Daemon, _ = strconv.ParseBool(val)
	} else {
		secretInitConfig.Daemon, _ = strconv.ParseBool(viper.GetString(SecretInitDaemonEnvVar))
	}

	if val, ok := annotations[SecretInitDelayAnnotation]; ok {
		secretInitConfig.Delay, _ = time.ParseDuration(val)
	} else {
		secretInitConfig.Delay, _ = time.ParseDuration(viper.GetString(SecretInitDelayEnvVar))
	}

	if val, ok := annotations[SecretInitJSONLogAnnotation]; ok {
		secretInitConfig.JSONLog = val
	} else {
		secretInitConfig.JSONLog = viper.GetString(SecretInitJSONLogEnvVar)
	}

	if val, ok := annotations[SecretInitImageAnnotation]; ok {
		secretInitConfig.Image = val
	} else {
		secretInitConfig.Image = viper.GetString(SecretInitImageEnvVar)
	}

	secretInitConfig.LogServer = viper.GetString(SecretInitLogServerEnvVar)

	secretInitConfig.LogLevel = viper.GetString(SecretInitLogLevelEnvVar)

	if val, ok := annotations[SecretInitImagePullPolicyAnnotation]; ok {
		secretInitConfig.ImagePullPolicy = GetPullPolicy(val)
	} else {
		secretInitConfig.ImagePullPolicy = GetPullPolicy(viper.GetString(SecretInitImagePullPolicyEnvVar))
	}

	if val, err := resource.ParseQuantity(viper.GetString(SecretInitCPURequestEnvVar)); err == nil {
		secretInitConfig.CPURequest = val
	} else {
		secretInitConfig.CPURequest = resource.MustParse("50m")
	}

	if val, err := resource.ParseQuantity(viper.GetString(SecretInitMemoryRequestEnvVar)); err == nil {
		secretInitConfig.MemoryRequest = val
	} else {
		secretInitConfig.MemoryRequest = resource.MustParse("64Mi")
	}

	if val, err := resource.ParseQuantity(viper.GetString(SecretInitCPULimitEnvVar)); err == nil {
		secretInitConfig.CPULimit = val
	} else {
		secretInitConfig.CPULimit = resource.MustParse("250m")
	}

	if val, err := resource.ParseQuantity(viper.GetString(SecretInitMemoryLimitEnvVar)); err == nil {
		secretInitConfig.MemoryLimit = val
	} else {
		secretInitConfig.MemoryLimit = resource.MustParse("64Mi")
	}

	return secretInitConfig
}

func SetConfigDefaults() {
	// Webhook defaults
	viper.SetDefault(PSPAllowPrivilegeEscalationEnvVar, "false")
	viper.SetDefault(RunAsNonRootEnvVar, "false")
	viper.SetDefault(RunAsUserEnvVar, "0")
	viper.SetDefault(RunAsGroupEnvVar, "0")
	viper.SetDefault(ReadonlyRootFSEnvVar, "false")
	viper.SetDefault(RegistrySkipVerifyEnvVar, "false")
	viper.SetDefault(MutateConfigMapEnvVar, "false")
	viper.SetDefault(DefaultImagePullSecretEnvVar, "")
	viper.SetDefault(DefaultImagePullSecretSAEnvVar, "")
	viper.SetDefault(DefaultImagePullSecretNSEnvVar, "")
	viper.SetDefault(TLSCertFileEnvVar, "")
	viper.SetDefault(TLSPrivateKeyFileEnvVar, "")
	viper.SetDefault(ListenAddressEnvVar, ":8443")
	viper.SetDefault(TelemetryListenAddressEnvVar, "")
	viper.SetDefault(LogLevelEnvVar, "info")

	// Secret-init defaults
	viper.SetDefault(SecretInitDaemonEnvVar, "false")
	viper.SetDefault(SecretInitJSONLogEnvVar, "false")
	viper.SetDefault(SecretInitImageEnvVar, "ghcr.io/bank-vaults/secret-init:latest")
	viper.SetDefault(SecretInitImagePullPolicyEnvVar, string(corev1.PullIfNotPresent))
	viper.SetDefault(SecretInitCPURequestEnvVar, "")
	viper.SetDefault(SecretInitMemoryRequestEnvVar, "")
	viper.SetDefault(SecretInitCPULimitEnvVar, "")
	viper.SetDefault(SecretInitMemoryLimitEnvVar, "")
	viper.SetDefault(SecretInitLogServerEnvVar, "")
	viper.SetDefault(SecretInitLogLevelEnvVar, "info")

	viper.AutomaticEnv()
}

// This is implemented to preserve backwards compatibility with the deprecated annotations
func handleDeprecatedAnnotations(annotations map[string]string) map[string]string {
	if val, ok := annotations[MutateAnnotationDeprecated]; ok {
		annotations[MutateAnnotation] = val
		delete(annotations, MutateAnnotationDeprecated)

		// Do an early exit if the resource shouldn't be mutated
		if val == "skip" {
			return annotations
		}
	}

	if val, ok := annotations[PSPAllowPrivilegeEscalationAnnotationDeprecated]; ok {
		annotations[PSPAllowPrivilegeEscalationAnnotation] = val
		delete(annotations, PSPAllowPrivilegeEscalationAnnotationDeprecated)
	}

	if val, ok := annotations[RunAsNonRootAnnotationDeprecated]; ok {
		annotations[RunAsNonRootAnnotation] = val
		delete(annotations, RunAsNonRootAnnotationDeprecated)
	}

	if val, ok := annotations[RunAsUserAnnotationDeprecated]; ok {
		annotations[RunAsUserAnnotation] = val
		delete(annotations, RunAsUserAnnotationDeprecated)
	}

	if val, ok := annotations[RunAsGroupAnnotationDeprecated]; ok {
		annotations[RunAsGroupAnnotation] = val
		delete(annotations, RunAsGroupAnnotationDeprecated)
	}

	if val, ok := annotations[ReadOnlyRootFsAnnotationDeprecated]; ok {
		annotations[ReadOnlyRootFsAnnotation] = val
		delete(annotations, ReadOnlyRootFsAnnotationDeprecated)
	}

	if val, ok := annotations[RegistrySkipVerifyAnnotationDeprecated]; ok {
		annotations[RegistrySkipVerifyAnnotation] = val
		delete(annotations, RegistrySkipVerifyAnnotationDeprecated)
	}

	if val, ok := annotations[MutateProbesAnnotationDeprecated]; ok {
		annotations[MutateProbesAnnotation] = val
		delete(annotations, MutateProbesAnnotationDeprecated)
	}

	if val, ok := annotations[VaultEnvDaemonAnnotationDeprecated]; ok {
		annotations[SecretInitDaemonAnnotation] = val
		delete(annotations, VaultEnvDaemonAnnotationDeprecated)
	}

	if val, ok := annotations[VaultEnvDelayAnnotationDeprecated]; ok {
		annotations[SecretInitDelayAnnotation] = val
		delete(annotations, VaultEnvDelayAnnotationDeprecated)
	}

	if val, ok := annotations[VaultEnvEnableJSONLogAnnotationDeprecated]; ok {
		annotations[SecretInitJSONLogAnnotation] = val
		delete(annotations, VaultEnvEnableJSONLogAnnotationDeprecated)
	}

	if val, ok := annotations[VaultEnvImageAnnotationDeprecated]; ok {
		annotations[SecretInitImageAnnotation] = val
		delete(annotations, VaultEnvImageAnnotationDeprecated)
	}

	if val, ok := annotations[VaultEnvImagePullPolicyAnnotationDeprecated]; ok {
		annotations[SecretInitImagePullPolicyAnnotation] = val
		delete(annotations, VaultEnvImagePullPolicyAnnotationDeprecated)
	}

	return annotations
}

func handleDeprecatedEnvVars() {
	if val := viper.GetString(VaultEnvDaemonEnvVarDeprecated); val != "" {
		viper.Set(SecretInitDaemonEnvVar, val)
	}

	if val := viper.GetString(VaultEnvDelayEnvVarDeprecated); val != "" {
		viper.Set(SecretInitDelayEnvVar, val)
	}

	if val := viper.GetString(VaultEnvPassthroughEnvVarDeprecated); val != "" {
		viper.Set(VaultPassthroughEnvVar, val)
	}

	if val := viper.GetString(VaultEnvEnableJSONLogEnvVarDeprecated); val != "" {
		viper.Set(SecretInitJSONLogEnvVar, val)
	}

	if val := viper.GetString(VaultEnvImageEnvVarDeprecated); val != "" {
		viper.Set(SecretInitImageEnvVar, val)
	}

	if val := viper.GetString(VaultEnvLogServerEnvVarDeprecated); val != "" {
		viper.Set(SecretInitLogServerEnvVar, val)
	}

	if val := viper.GetString(VaultEnvImagePullPolicyEnvVarDeprecated); val != "" {
		viper.Set(SecretInitImagePullPolicyEnvVar, val)
	}

	if val := viper.GetString(VaultEnvCPURequestEnvVarDeprecated); val != "" {
		viper.Set(SecretInitCPURequestEnvVar, val)
	}

	if val := viper.GetString(VaultEnvMemoryRequestEnvVarDeprecated); val != "" {
		viper.Set(SecretInitMemoryRequestEnvVar, val)
	}

	if val := viper.GetString(VaultEnvCPULimitEnvVarDeprecated); val != "" {
		viper.Set(SecretInitCPULimitEnvVar, val)
	}

	if val := viper.GetString(VaultEnvMemoryLimitEnvVarDeprecated); val != "" {
		viper.Set(SecretInitMemoryLimitEnvVar, val)
	}
}
