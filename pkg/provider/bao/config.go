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

package bao

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
                        path = "/bao/.bao-token"
                }
        }
}`
	ProviderName = "bao"
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
	BaoNamespace                  string
	BaoServiceAccount             string
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

	if val, ok := annotations[common.BaoAddrAnnotation]; ok {
		config.Addr = val
	} else {
		config.Addr = viper.GetString("bao_addr")
	}

	if val, ok := annotations[common.BaoRoleAnnotation]; ok {
		config.Role = val
	} else {
		if val := viper.GetString("bao_role"); val != "" {
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

	if val, ok := annotations[common.BaoAuthMethodAnnotation]; ok {
		config.AuthMethod = val
	} else {
		config.AuthMethod = viper.GetString("bao_auth_method")
	}

	if val, ok := annotations[common.BaoPathAnnotation]; ok {
		config.Path = val
	} else {
		config.Path = viper.GetString("bao_path")
	}

	// TODO: Check for flag to verify we want to use namespace-local SAs instead of the webhook namespaces SA
	if val, ok := annotations[common.BaoServiceaccountAnnotation]; ok {
		config.BaoServiceAccount = val
	} else {
		config.BaoServiceAccount = viper.GetString("bao_serviceaccount")
	}

	if val, ok := annotations[common.BaoSkipVerifyAnnotation]; ok {
		config.SkipVerify, _ = strconv.ParseBool(val)
	} else {
		config.SkipVerify = viper.GetBool("bao_skip_verify")
	}

	if val, ok := annotations[common.BaoTLSSecretAnnotation]; ok {
		config.TLSSecret = val
	} else {
		config.TLSSecret = viper.GetString("bao_tls_secret")
	}

	if val, ok := annotations[common.BaoClientTimeoutAnnotation]; ok {
		config.ClientTimeout, _ = time.ParseDuration(val)
	} else {
		config.ClientTimeout, _ = time.ParseDuration(viper.GetString("bao_client_timeout"))
	}

	if val, ok := annotations[common.BaoAgentAnnotation]; ok {
		config.UseAgent, _ = strconv.ParseBool(val)
	} else {
		config.UseAgent, _ = strconv.ParseBool(viper.GetString("bao_agent"))
	}

	if val, ok := annotations[common.BaoConsulTemplateConfigmapAnnotation]; ok {
		config.CtConfigMap = val
	} else {
		config.CtConfigMap = ""
	}

	if val, ok := annotations[common.BaoServiceAccountTokenVolumeNameAnnotation]; ok {
		config.ServiceAccountTokenVolumeName = val
	} else if viper.GetString("SERVICE_ACCOUNT_TOKEN_VOLUME_NAME") != "" {
		config.ServiceAccountTokenVolumeName = viper.GetString("SERVICE_ACCOUNT_TOKEN_VOLUME_NAME")
	} else {
		config.ServiceAccountTokenVolumeName = "/var/run/secrets/kubernetes.io/serviceaccount"
	}

	if val, ok := annotations[common.BaoConsulTemplateImageAnnotation]; ok {
		config.CtImage = val
	} else {
		config.CtImage = viper.GetString("bao_ct_image")
	}

	if val, ok := annotations[common.BaoIgnoreMissingSecretsAnnotation]; ok {
		config.IgnoreMissingSecrets = val
	} else {
		config.IgnoreMissingSecrets = viper.GetString("bao_ignore_missing_secrets")
	}

	if val, ok := annotations[common.BaoPassthroughAnnotation]; ok {
		config.Passthrough = val
	} else {
		config.Passthrough = viper.GetString("bao_passthrough")
	}

	if val, ok := annotations[common.BaoConfigfilePathAnnotation]; ok {
		config.ConfigfilePath = val
	} else if val, ok := annotations[common.BaoConsulTemplateSecretsMountPathAnnotation]; ok {
		config.ConfigfilePath = val
	} else {
		config.ConfigfilePath = "/bao/secrets"
	}

	if val, ok := annotations[common.BaoConsulTemplatePullPolicyAnnotation]; ok {
		config.CtImagePullPolicy = common.GetPullPolicy(val)
	} else {
		config.CtImagePullPolicy = common.GetPullPolicy(viper.GetString("bao_ct_pull_policy"))
	}

	if val, ok := annotations[common.BaoConsulTemplateOnceAnnotation]; ok {
		config.CtOnce, _ = strconv.ParseBool(val)
	} else {
		config.CtOnce = false
	}

	if val, err := resource.ParseQuantity(annotations[common.BaoConsulTemplateCPUAnnotation]); err == nil {
		config.CtCPU = val
	} else {
		config.CtCPU = resource.MustParse("100m")
	}

	if val, err := resource.ParseQuantity(annotations[common.BaoConsulTemplateMemoryAnnotation]); err == nil {
		config.CtMemory = val
	} else {
		config.CtMemory = resource.MustParse("128Mi")
	}

	if val, ok := annotations[common.BaoConsulTemplateShareProcessNamespaceAnnotation]; ok {
		config.CtShareProcessDefault = "found"
		config.CtShareProcess, _ = strconv.ParseBool(val)
	} else {
		config.CtShareProcessDefault = "empty"
		config.CtShareProcess = false
	}

	if val, ok := annotations[common.BaoLogLevelAnnotation]; ok {
		config.LogLevel = val
	} else {
		config.LogLevel = viper.GetString("bao_log_level")
	}

	if val, ok := annotations[common.BaoTransitKeyIDAnnotation]; ok {
		config.TransitKeyID = val
	} else {
		config.TransitKeyID = viper.GetString("transit_key_id")
	}

	if val, ok := annotations[common.BaoTransitPathAnnotation]; ok {
		config.TransitPath = val
	} else {
		config.TransitPath = viper.GetString("transit_path")
	}

	if val, ok := annotations[common.BaoAgentConfigmapAnnotation]; ok {
		config.AgentConfigMap = val
	} else {
		config.AgentConfigMap = ""
	}

	if val, ok := annotations[common.BaoAgentOnceAnnotation]; ok {
		config.AgentOnce, _ = strconv.ParseBool(val)
	} else {
		config.AgentOnce = false
	}

	if val, err := resource.ParseQuantity(annotations[common.BaoAgentCPUAnnotation]); err == nil {
		config.AgentCPULimit = val
	} else if val, err := resource.ParseQuantity(annotations[common.BaoAgentCPULimitAnnotation]); err == nil {
		config.AgentCPULimit = val
	} else {
		config.AgentCPULimit = resource.MustParse("100m")
	}

	if val, err := resource.ParseQuantity(annotations[common.BaoAgentMemoryAnnotation]); err == nil {
		config.AgentMemoryLimit = val
	} else if val, err := resource.ParseQuantity(annotations[common.BaoAgentMemoryLimitAnnotation]); err == nil {
		config.AgentMemoryLimit = val
	} else {
		config.AgentMemoryLimit = resource.MustParse("128Mi")
	}

	if val, err := resource.ParseQuantity(annotations[common.BaoAgentCPURequestAnnotation]); err == nil {
		config.AgentCPURequest = val
	} else {
		config.AgentCPURequest = resource.MustParse("100m")
	}

	if val, err := resource.ParseQuantity(annotations[common.BaoAgentMemoryRequestAnnotation]); err == nil {
		config.AgentMemoryRequest = val
	} else {
		config.AgentMemoryRequest = resource.MustParse("128Mi")
	}

	if val, ok := annotations[common.BaoAgentShareProcessNamespaceAnnotation]; ok {
		config.AgentShareProcessDefault = "found"
		config.AgentShareProcess, _ = strconv.ParseBool(val)
	} else {
		config.AgentShareProcessDefault = "empty"
		config.AgentShareProcess = false
	}

	if val, ok := annotations[common.BaoFromPathAnnotation]; ok {
		config.FromPath = val
	}

	if val, ok := annotations[common.BaoTokenAuthMountAnnotation]; ok {
		config.TokenAuthMount = val
	}

	if val, ok := annotations[common.BaoImageAnnotation]; ok {
		config.AgentImage = val
	} else {
		config.AgentImage = viper.GetString("bao_image")
	}

	if val, ok := annotations[common.BaoImagePullPolicyAnnotation]; ok {
		config.AgentImagePullPolicy = common.GetPullPolicy(val)
	} else {
		config.AgentImagePullPolicy = common.GetPullPolicy(viper.GetString("bao_image_pull_policy"))
	}

	if val, ok := annotations[common.BaoAgentEnvVariablesAnnotation]; ok {
		config.AgentEnvVariables = val
	}

	if val, ok := annotations[common.BaoNamespaceAnnotation]; ok {
		config.BaoNamespace = val
	} else {
		config.BaoNamespace = viper.GetString("BAO_NAMESPACE")
	}

	if val, ok := annotations[common.BaoConsulTemplateInjectInInitcontainersAnnotation]; ok {
		config.CtInjectInInitcontainers, _ = strconv.ParseBool(val)
	} else {
		config.CtInjectInInitcontainers = false
	}

	if val, ok := annotations[common.BaoTransitBatchSizeAnnotation]; ok {
		batchSize, _ := strconv.ParseInt(val, 10, 32)
		config.TransitBatchSize = int(batchSize)
	} else {
		config.TransitBatchSize = viper.GetInt("bao_transit_batch_size")
	}

	config.Token = viper.GetString("bao_token")

	// parse resulting config.Role as potential template with fields of Config
	tmpl, err := template.New("baoRole").Option("missingkey=error").Parse(config.Role)
	if err != nil {
		return Config{}, errors.Wrap(err, "error parsing bao_role")
	}

	var vRoleBuf strings.Builder
	if err = tmpl.Execute(&vRoleBuf, map[string]string{
		"authmethod":     config.AuthMethod,
		"name":           obj.GetName(),
		"namespace":      config.ObjectNamespace,
		"path":           config.Path,
		"serviceaccount": config.BaoServiceAccount,
	}); err != nil {
		return Config{}, errors.Wrap(err, "error templating bao_role")
	}

	config.Role = vRoleBuf.String()
	slog.Debug(fmt.Sprintf("config.Role = '%s'", config.Role))

	return config, nil
}

func SetDefaults() {
	viper.SetDefault("bao_image", "csatib02/opanbao:dev")
	viper.SetDefault("bao_image_pull_policy", string(corev1.PullIfNotPresent))
	viper.SetDefault("bao_ct_image", "hashicorp/consul-template:0.32.0")
	viper.SetDefault("bao_ct_pull_policy", string(corev1.PullIfNotPresent))
	viper.SetDefault("bao_addr", "https://bao:8300")
	viper.SetDefault("bao_skip_verify", "false")
	viper.SetDefault("bao_path", "kubernetes")
	viper.SetDefault("bao_auth_method", "jwt")
	viper.SetDefault("bao_role", "")
	viper.SetDefault("bao_tls_secret", "")
	viper.SetDefault("bao_client_timeout", "10s")
	viper.SetDefault("bao_agent", "false")
	viper.SetDefault("bao_ct_share_process_namespace", "")
	viper.SetDefault("bao_ignore_missing_secrets", "false")
	viper.SetDefault("bao_passthrough", "")
	viper.SetDefault("bao_agent_share_process_namespace", "")
	viper.SetDefault("bao_log_level", "info")
	viper.SetDefault("BAO_NAMESPACE", "")
	viper.SetDefault("bao_transit_key_id", "")
	viper.SetDefault("bao_transit_path", "")
	viper.SetDefault("bao_transit_batch_size", 25)
	viper.AutomaticEnv()
}
