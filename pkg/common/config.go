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

package common

import (
	"strconv"
	"strings"
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
	Providers                   []string
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

func ParseWebhookConfig(obj metav1.Object) Config {
	Config := Config{}

	annotations := obj.GetAnnotations()

	if val, ok := annotations[MutateAnnotation]; ok {
		Config.Mutate, _ = strconv.ParseBool(val)
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

	if val, ok := annotations[ProvidersAnnotation]; ok {
		Config.Providers = strings.Split(val, ",")
	}

	return Config
}

func ParseSecretInitConfig(obj metav1.Object) SecretInitConfig {
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

	secretInitConfig.LogServer = viper.GetString("SECRET_INIT_LOG_SERVER")

	secretInitConfig.LogLevel = viper.GetString("SECRET_INIT_LOG_LEVEL")

	if val, ok := annotations[SecretInitImagePullPolicyAnnotation]; ok {
		secretInitConfig.ImagePullPolicy = GetPullPolicy(val)
	} else {
		secretInitConfig.ImagePullPolicy = GetPullPolicy(viper.GetString("secret_init_image_pull_policy"))
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

func SetWebhookAndSecretInitDefaults() {
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
	viper.SetDefault("SECRET_INIT_CPU_REQUEST", "")
	viper.SetDefault("SECRET_INIT_MEMORY_REQUEST", "")
	viper.SetDefault("SECRET_INIT_CPU_LIMIT", "")
	viper.SetDefault("SECRET_INIT_MEMORY_LIMIT", "")
	viper.SetDefault("SECRET_INIT_LOG_SERVER", "")
	viper.SetDefault("SECRET_INIT_LOG_LEVEL", "info")
	viper.AutomaticEnv()
}
