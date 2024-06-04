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
)

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

func LoadSecretInitConfig(annotations map[string]string) SecretInitConfig {
	setSecretInitConfigDefaults()
	handleDeprecatedSecretInitEnvVars()

	secretInitConfig := SecretInitConfig{}

	if val, ok := annotations[SecretInitDaemonAnnotation]; ok {
		secretInitConfig.Daemon, _ = strconv.ParseBool(val)
	} else if val, ok := annotations[VaultEnvDaemonAnnotationDeprecated]; ok {
		secretInitConfig.Daemon, _ = strconv.ParseBool(val)
	} else {
		secretInitConfig.Daemon, _ = strconv.ParseBool(viper.GetString(SecretInitDaemonEnvVar))
	}

	if val, ok := annotations[SecretInitDelayAnnotation]; ok {
		secretInitConfig.Delay, _ = time.ParseDuration(val)
	} else if val, ok := annotations[VaultEnvDelayAnnotationDeprecated]; ok {
		secretInitConfig.Delay, _ = time.ParseDuration(val)
	} else {
		secretInitConfig.Delay, _ = time.ParseDuration(viper.GetString(SecretInitDelayEnvVar))
	}

	if val, ok := annotations[SecretInitJSONLogAnnotation]; ok {
		secretInitConfig.JSONLog = val
	} else if val, ok := annotations[VaultEnvEnableJSONLogAnnotationDeprecated]; ok {
		secretInitConfig.JSONLog = val
	} else {
		secretInitConfig.JSONLog = viper.GetString(SecretInitJSONLogEnvVar)
	}

	if val, ok := annotations[SecretInitImageAnnotation]; ok {
		secretInitConfig.Image = val
	} else if val, ok := annotations[VaultEnvImageAnnotationDeprecated]; ok {
		secretInitConfig.Image = val
	} else {
		secretInitConfig.Image = viper.GetString(SecretInitImageEnvVar)
	}

	if val, ok := annotations[SecretInitImagePullPolicyAnnotation]; ok {
		secretInitConfig.ImagePullPolicy = GetPullPolicy(val)
	} else if val, ok := annotations[VaultEnvImagePullPolicyAnnotationDeprecated]; ok {
		secretInitConfig.ImagePullPolicy = GetPullPolicy(val)
	} else {
		secretInitConfig.ImagePullPolicy = GetPullPolicy(viper.GetString(SecretInitImagePullPolicyEnvVar))
	}

	secretInitConfig.LogServer = viper.GetString(SecretInitLogServerEnvVar)

	secretInitConfig.LogLevel = viper.GetString(SecretInitLogLevelEnvVar)

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

func setSecretInitConfigDefaults() {
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

func handleDeprecatedSecretInitEnvVars() {
	if val := viper.GetString(VaultEnvDaemonEnvVarDeprecated); val != "" {
		viper.Set(SecretInitDaemonEnvVar, val)
	}

	if val := viper.GetString(VaultEnvDelayEnvVarDeprecated); val != "" {
		viper.Set(SecretInitDelayEnvVar, val)
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
