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
	Config := Config{}

	annotations := handleDeprecatedAnnotations(obj.GetAnnotations())

	if val := annotations[MutateAnnotation]; val == "skip" {
		Config.Mutate = true

		return Config
	}

	if val, ok := annotations[PSPAllowPrivilegeEscalationAnnotation]; ok {
		Config.PspAllowPrivilegeEscalation, _ = strconv.ParseBool(val)
	}

	if val, ok := annotations[RunAsNonRootAnnotation]; ok {
		Config.RunAsNonRoot, _ = strconv.ParseBool(val)
	}

	if val, ok := annotations[RunAsUserAnnotation]; ok {
		Config.RunAsUser, _ = strconv.ParseInt(val, 10, 64)
	}

	if val, ok := annotations[RunAsGroupAnnotation]; ok {
		Config.RunAsGroup, _ = strconv.ParseInt(val, 10, 64)
	}

	if val, ok := annotations[ReadOnlyRootFsAnnotation]; ok {
		Config.ReadOnlyRootFilesystem, _ = strconv.ParseBool(val)
	}

	if val, ok := annotations[RegistrySkipVerifyAnnotation]; ok {
		Config.RegistrySkipVerify, _ = strconv.ParseBool(val)
	}

	if val, ok := annotations[MutateProbesAnnotation]; ok {
		Config.MutateProbes, _ = strconv.ParseBool(val)
	}

	if val, ok := annotations[ProviderAnnotation]; ok {
		Config.Provider = val
	}

	return Config
}

func LoadSecretInitConfig(obj metav1.Object) SecretInitConfig {
	secretInitConfig := SecretInitConfig{}

	annotations := obj.GetAnnotations()

	if val, ok := annotations[SecretInitDaemonAnnotation]; ok {
		secretInitConfig.Daemon, _ = strconv.ParseBool(val)
	} else {
		secretInitConfig.Daemon, _ = strconv.ParseBool(viper.GetString("secret_init_daemon"))
	}

	if val, ok := annotations[SecretInitDelayAnnotation]; ok {
		secretInitConfig.Delay, _ = time.ParseDuration(val)
	} else {
		secretInitConfig.Delay, _ = time.ParseDuration(viper.GetString("secret_init_delay"))
	}

	if val, ok := annotations[SecretInitJSONLogAnnotation]; ok {
		secretInitConfig.JSONLog = val
	} else {
		secretInitConfig.JSONLog = viper.GetString("secret_init_json_log")
	}

	if val, ok := annotations[SecretInitImageAnnotation]; ok {
		secretInitConfig.Image = val
	} else {
		secretInitConfig.Image = viper.GetString("secret_init_image")
	}

	secretInitConfig.LogServer = viper.GetString("secret_init_log_server")

	secretInitConfig.LogLevel = viper.GetString("secret_init_log_level")

	if val, ok := annotations[SecretInitImagePullPolicyAnnotation]; ok {
		secretInitConfig.ImagePullPolicy = GetPullPolicy(val)
	} else {
		secretInitConfig.ImagePullPolicy = GetPullPolicy(viper.GetString("secret_init_image_pull_policy"))
	}

	if val, err := resource.ParseQuantity(viper.GetString("secret_init_cpu_request")); err == nil {
		secretInitConfig.CPURequest = val
	} else {
		secretInitConfig.CPURequest = resource.MustParse("50m")
	}

	if val, err := resource.ParseQuantity(viper.GetString("secret_init_memory_request")); err == nil {
		secretInitConfig.MemoryRequest = val
	} else {
		secretInitConfig.MemoryRequest = resource.MustParse("64Mi")
	}

	if val, err := resource.ParseQuantity(viper.GetString("secret_init_cpu_limit")); err == nil {
		secretInitConfig.CPULimit = val
	} else {
		secretInitConfig.CPULimit = resource.MustParse("250m")
	}

	if val, err := resource.ParseQuantity(viper.GetString("secret_init_memory_limit")); err == nil {
		secretInitConfig.MemoryLimit = val
	} else {
		secretInitConfig.MemoryLimit = resource.MustParse("64Mi")
	}

	return secretInitConfig
}

func SetConfigDefaults() {
	// Webhook defaults
	viper.SetDefault("psp_allow_privilege_escalation", "false")
	viper.SetDefault("run_as_non_root", "false")
	viper.SetDefault("run_as_user", "0")
	viper.SetDefault("run_as_group", "0")
	viper.SetDefault("readonly_root_fs", "false")
	viper.SetDefault("registry_skip_verify", "false")
	viper.SetDefault("mutate_configmap", "false")
	viper.SetDefault("default_image_pull_secret", "")
	viper.SetDefault("default_image_pull_secret_service_account", "")
	viper.SetDefault("default_image_pull_secret_namespace", "")
	viper.SetDefault("tls_cert_file", "")
	viper.SetDefault("tls_private_key_file", "")
	viper.SetDefault("listen_address", ":8443")
	viper.SetDefault("telemetry_listen_address", "")
	viper.SetDefault("log_level", "info")

	// Secret-init defaults
	viper.SetDefault("secret_init_daemon", "false")
	viper.SetDefault("secret_init_json_log", "false")
	viper.SetDefault("secret_init_image", "ghcr.io/bank-vaults/secret-init:latest")
	viper.SetDefault("secret_init_image_pull_policy", string(corev1.PullIfNotPresent))
	viper.SetDefault("secret_init_cpu_request", "")
	viper.SetDefault("secret_init_memory_request", "")
	viper.SetDefault("secret_init_cpu_limit", "")
	viper.SetDefault("secret_init_memory_limit", "")
	viper.SetDefault("secret_init_log_server", "")
	viper.SetDefault("secret_init_log_level", "info")

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
