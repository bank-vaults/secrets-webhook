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
	"context"
	"log/slog"
	"testing"
	"time"

	cmp "github.com/google/go-cmp/cmp"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/slok/kubewebhook/v2/pkg/model"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	fake "k8s.io/client-go/kubernetes/fake"

	"github.com/bank-vaults/secrets-webhook/pkg/common"
	"github.com/bank-vaults/secrets-webhook/pkg/provider/vault"
)

var (
	webhookConfig = common.Config{
		RunAsNonRoot: true,
		RunAsUser:    int64(1000),
		RunAsGroup:   int64(1000),
	}

	secretInitConfig = common.SecretInitConfig{
		JSONLog: "enableJSONLog",
	}

	providerConfigs = map[string]interface{}{
		vault.ProviderName: vault.Config{
			Addr:                 "addr",
			SkipVerify:           false,
			Path:                 "path",
			Role:                 "role",
			AuthMethod:           "jwt",
			IgnoreMissingSecrets: "ignoreMissingSecrets",
			Passthrough:          "vaultPassthrough",
			ClientTimeout:        10 * time.Second,
		},
	}
)

type MockRegistry struct {
	Image v1.Config
}

func (r *MockRegistry) GetImageConfig(_ context.Context, _ kubernetes.Interface, _ string, _ bool, _ *corev1.Container, _ *corev1.PodSpec) (*v1.Config, error) {
	return &r.Image, nil
}

func Test_mutatingWebhook_mutateContainers_Vault(t *testing.T) {
	vaultConfigEnvFrom := providerConfigs[vault.ProviderName].(vault.Config)
	vaultConfigEnvFrom.FromPath = "secrets/application"

	type fields struct {
		k8sClient kubernetes.Interface
		registry  ImageRegistry
	}
	type args struct {
		containers       []corev1.Container
		podSpec          *corev1.PodSpec
		webhookConfig    common.Config
		SecretInitConfig common.SecretInitConfig
		vaultConfig      vault.Config
	}
	tests := []struct {
		name             string
		fields           fields
		args             args
		mutated          bool
		wantErr          bool
		wantedContainers []corev1.Container
	}{
		{
			name: "Will mutate container with command, no args",
			fields: fields{
				k8sClient: fake.NewSimpleClientset(),
				registry: &MockRegistry{
					Image: v1.Config{},
				},
			},
			args: args{
				containers: []corev1.Container{
					{
						Name:    "MyContainer",
						Image:   "myimage",
						Command: []string{"/bin/bash"},
						Args:    nil,
						Env: []corev1.EnvVar{
							{
								Name:  "myvar",
								Value: "vault:secrets",
							},
						},
					},
				},
				webhookConfig:    webhookConfig,
				SecretInitConfig: secretInitConfig,
				vaultConfig:      providerConfigs[vault.ProviderName].(vault.Config),
			},
			wantedContainers: []corev1.Container{
				{
					Name:         "MyContainer",
					Image:        "myimage",
					Command:      []string{"/bank-vaults/secret-init"},
					Args:         []string{"/bin/bash"},
					VolumeMounts: []corev1.VolumeMount{{Name: "secret-init", MountPath: "/bank-vaults/"}},
					Env: []corev1.EnvVar{
						{Name: "myvar", Value: "vault:secrets"},
						{Name: "VAULT_ADDR", Value: "addr"},
						{Name: "VAULT_SKIP_VERIFY", Value: "false"},
						{Name: "VAULT_AUTH_METHOD", Value: "jwt"},
						{Name: "VAULT_PATH", Value: "path"},
						{Name: "VAULT_ROLE", Value: "role"},
						{Name: "VAULT_IGNORE_MISSING_SECRETS", Value: "ignoreMissingSecrets"},
						{Name: "VAULT_PASSTHROUGH", Value: "vaultPassthrough"},
						{Name: "SECRET_INIT_JSON_LOG", Value: "enableJSONLog"},
						{Name: "VAULT_CLIENT_TIMEOUT", Value: "10s"},
					},
				},
			},
			mutated: true,
			wantErr: false,
		},
		{
			name: "Will mutate container with command, other syntax",
			fields: fields{
				k8sClient: fake.NewSimpleClientset(),
				registry: &MockRegistry{
					Image: v1.Config{},
				},
			},
			args: args{
				containers: []corev1.Container{
					{
						Name:    "MyContainer",
						Image:   "myimage",
						Command: []string{"/bin/bash"},
						Args:    nil,
						Env: []corev1.EnvVar{
							{
								Name:  "myvar",
								Value: ">>vault:secrets",
							},
						},
					},
				},
				webhookConfig:    webhookConfig,
				SecretInitConfig: secretInitConfig,
				vaultConfig:      providerConfigs[vault.ProviderName].(vault.Config),
			},
			wantedContainers: []corev1.Container{
				{
					Name:         "MyContainer",
					Image:        "myimage",
					Command:      []string{"/bank-vaults/secret-init"},
					Args:         []string{"/bin/bash"},
					VolumeMounts: []corev1.VolumeMount{{Name: "secret-init", MountPath: "/bank-vaults/"}},
					Env: []corev1.EnvVar{
						{Name: "myvar", Value: ">>vault:secrets"},
						{Name: "VAULT_ADDR", Value: "addr"},
						{Name: "VAULT_SKIP_VERIFY", Value: "false"},
						{Name: "VAULT_AUTH_METHOD", Value: "jwt"},
						{Name: "VAULT_PATH", Value: "path"},
						{Name: "VAULT_ROLE", Value: "role"},
						{Name: "VAULT_IGNORE_MISSING_SECRETS", Value: "ignoreMissingSecrets"},
						{Name: "VAULT_PASSTHROUGH", Value: "vaultPassthrough"},
						{Name: "SECRET_INIT_JSON_LOG", Value: "enableJSONLog"},
						{Name: "VAULT_CLIENT_TIMEOUT", Value: "10s"},
					},
				},
			},
			mutated: true,
			wantErr: false,
		},
		{
			name: "Will mutate container with args, no command",
			fields: fields{
				k8sClient: fake.NewSimpleClientset(),
				registry: &MockRegistry{
					Image: v1.Config{
						Entrypoint: []string{"myEntryPoint"},
					},
				},
			},
			args: args{
				containers: []corev1.Container{
					{
						Name:    "MyContainer",
						Image:   "myimage",
						Command: []string{},
						Args:    nil,
						Env: []corev1.EnvVar{
							{
								Name:  "myvar",
								Value: ">>vault:secrets",
							},
						},
					},
				},
				webhookConfig:    webhookConfig,
				SecretInitConfig: secretInitConfig,
				vaultConfig:      providerConfigs[vault.ProviderName].(vault.Config),
			},
			wantedContainers: []corev1.Container{
				{
					Name:         "MyContainer",
					Image:        "myimage",
					Command:      []string{"/bank-vaults/secret-init"},
					Args:         []string{"myEntryPoint"},
					VolumeMounts: []corev1.VolumeMount{{Name: "secret-init", MountPath: "/bank-vaults/"}},
					Env: []corev1.EnvVar{
						{Name: "myvar", Value: ">>vault:secrets"},
						{Name: "VAULT_ADDR", Value: "addr"},
						{Name: "VAULT_SKIP_VERIFY", Value: "false"},
						{Name: "VAULT_AUTH_METHOD", Value: "jwt"},
						{Name: "VAULT_PATH", Value: "path"},
						{Name: "VAULT_ROLE", Value: "role"},
						{Name: "VAULT_IGNORE_MISSING_SECRETS", Value: "ignoreMissingSecrets"},
						{Name: "VAULT_PASSTHROUGH", Value: "vaultPassthrough"},
						{Name: "SECRET_INIT_JSON_LOG", Value: "enableJSONLog"},
						{Name: "VAULT_CLIENT_TIMEOUT", Value: "10s"},
					},
				},
			},
			mutated: true,
			wantErr: false,
		},
		{
			name: "Will mutate container with probes",
			fields: fields{
				k8sClient: fake.NewSimpleClientset(),
				registry: &MockRegistry{
					Image: v1.Config{},
				},
			},
			args: args{
				containers: []corev1.Container{
					{
						Name:    "MyContainer",
						Image:   "myimage",
						Command: []string{"/bin/bash"},
						Args:    nil,
						LivenessProbe: &corev1.Probe{
							ProbeHandler: corev1.ProbeHandler{
								Exec: &corev1.ExecAction{
									Command: []string{"/bin/bash"},
								},
							},
						},
						Env: []corev1.EnvVar{
							{
								Name:  "myvar",
								Value: "vault:secrets",
							},
						},
					},
				},
				webhookConfig: common.Config{
					MutateProbes: true,
				},
				SecretInitConfig: common.SecretInitConfig{},
				vaultConfig:      vault.Config{},
			},
			wantedContainers: []corev1.Container{
				{
					Name:         "MyContainer",
					Image:        "myimage",
					Command:      []string{"/bank-vaults/secret-init"},
					Args:         []string{"/bin/bash"},
					VolumeMounts: []corev1.VolumeMount{{Name: "secret-init", MountPath: "/bank-vaults/"}},
					LivenessProbe: &corev1.Probe{
						ProbeHandler: corev1.ProbeHandler{
							Exec: &corev1.ExecAction{
								Command: []string{"/bank-vaults/secret-init", "/bin/bash"},
							},
						},
					},
					Env: []corev1.EnvVar{
						{Name: "myvar", Value: "vault:secrets"},
						{Name: "VAULT_ADDR", Value: ""},
						{Name: "VAULT_SKIP_VERIFY", Value: "false"},
						{Name: "VAULT_AUTH_METHOD", Value: ""},
						{Name: "VAULT_PATH", Value: ""},
						{Name: "VAULT_ROLE", Value: ""},
						{Name: "VAULT_IGNORE_MISSING_SECRETS", Value: ""},
						{Name: "VAULT_PASSTHROUGH", Value: ""},
						{Name: "SECRET_INIT_JSON_LOG", Value: ""},
						{Name: "VAULT_CLIENT_TIMEOUT", Value: "0s"},
					},
				},
			},
			mutated: true,
			wantErr: false,
		},
		{
			name: "Will mutate container with no container-command, no entrypoint",
			fields: fields{
				k8sClient: fake.NewSimpleClientset(),
				registry: &MockRegistry{
					Image: v1.Config{
						Cmd: []string{"myCmd"},
					},
				},
			},
			args: args{
				containers: []corev1.Container{
					{
						Name:    "MyContainer",
						Image:   "myimage",
						Command: []string{},
						Args:    nil,
						Env: []corev1.EnvVar{
							{
								Name:  "myvar",
								Value: ">>vault:secrets",
							},
						},
					},
				},
				webhookConfig:    webhookConfig,
				SecretInitConfig: secretInitConfig,
				vaultConfig:      providerConfigs[vault.ProviderName].(vault.Config),
			},
			wantedContainers: []corev1.Container{
				{
					Name:         "MyContainer",
					Image:        "myimage",
					Command:      []string{"/bank-vaults/secret-init"},
					Args:         []string{"myCmd"},
					VolumeMounts: []corev1.VolumeMount{{Name: "secret-init", MountPath: "/bank-vaults/"}},
					Env: []corev1.EnvVar{
						{Name: "myvar", Value: ">>vault:secrets"},
						{Name: "VAULT_ADDR", Value: "addr"},
						{Name: "VAULT_SKIP_VERIFY", Value: "false"},
						{Name: "VAULT_AUTH_METHOD", Value: "jwt"},
						{Name: "VAULT_PATH", Value: "path"},
						{Name: "VAULT_ROLE", Value: "role"},
						{Name: "VAULT_IGNORE_MISSING_SECRETS", Value: "ignoreMissingSecrets"},
						{Name: "VAULT_PASSTHROUGH", Value: "vaultPassthrough"},
						{Name: "SECRET_INIT_JSON_LOG", Value: "enableJSONLog"},
						{Name: "VAULT_CLIENT_TIMEOUT", Value: "10s"},
					},
				},
			},
			mutated: true,
			wantErr: false,
		},
		{
			name: "Will not mutate container without secrets with correct prefix",
			fields: fields{
				k8sClient: fake.NewSimpleClientset(),
				registry: &MockRegistry{
					Image: v1.Config{},
				},
			},
			args: args{
				containers: []corev1.Container{
					{
						Name:    "MyContainer",
						Image:   "myimage",
						Command: []string{"/bin/bash"},
					},
				},
				webhookConfig:    webhookConfig,
				SecretInitConfig: secretInitConfig,
				vaultConfig:      providerConfigs[vault.ProviderName].(vault.Config),
			},
			wantedContainers: []corev1.Container{
				{
					Name:    "MyContainer",
					Image:   "myimage",
					Command: []string{"/bin/bash"},
				},
			},
			mutated: false,
			wantErr: false,
		},
		{
			name: "Will mutate container with env-from-path annotation",
			fields: fields{
				k8sClient: fake.NewSimpleClientset(),
				registry: &MockRegistry{
					Image: v1.Config{},
				},
			},
			args: args{
				containers: []corev1.Container{
					{
						Name:    "MyContainer",
						Image:   "myimage",
						Command: []string{"/bin/bash"},
						Args:    nil,
						Env: []corev1.EnvVar{
							{
								Name:  "myvar",
								Value: "vault:secrets",
							},
						},
					},
				},
				webhookConfig:    webhookConfig,
				SecretInitConfig: secretInitConfig,
				vaultConfig:      vaultConfigEnvFrom,
			},
			wantedContainers: []corev1.Container{
				{
					Name:         "MyContainer",
					Image:        "myimage",
					Command:      []string{"/bank-vaults/secret-init"},
					Args:         []string{"/bin/bash"},
					VolumeMounts: []corev1.VolumeMount{{Name: "secret-init", MountPath: "/bank-vaults/"}},
					Env: []corev1.EnvVar{
						{Name: "myvar", Value: "vault:secrets"},
						{Name: "VAULT_ADDR", Value: "addr"},
						{Name: "VAULT_SKIP_VERIFY", Value: "false"},
						{Name: "VAULT_AUTH_METHOD", Value: "jwt"},
						{Name: "VAULT_PATH", Value: "path"},
						{Name: "VAULT_ROLE", Value: "role"},
						{Name: "VAULT_IGNORE_MISSING_SECRETS", Value: "ignoreMissingSecrets"},
						{Name: "VAULT_PASSTHROUGH", Value: "vaultPassthrough"},
						{Name: "SECRET_INIT_JSON_LOG", Value: "enableJSONLog"},
						{Name: "VAULT_CLIENT_TIMEOUT", Value: "10s"},
						{Name: "VAULT_FROM_PATH", Value: "secrets/application"},
					},
				},
			},
			mutated: true,
			wantErr: false,
		},
		{
			name: "Will mutate container with command, no args, with inline mutation",
			fields: fields{
				k8sClient: fake.NewSimpleClientset(),
				registry: &MockRegistry{
					Image: v1.Config{},
				},
			},
			args: args{
				containers: []corev1.Container{
					{
						Name:    "MyContainer",
						Image:   "myimage",
						Command: []string{"/bin/bash"},
						Args:    nil,
						Env: []corev1.EnvVar{
							{
								Name:  "myvar",
								Value: "scheme://${vault:secret/data/account#username}:${vault:secret/data/account#password}@127.0.0.1:8080",
							},
						},
					},
				},
				webhookConfig:    webhookConfig,
				SecretInitConfig: secretInitConfig,
				vaultConfig:      providerConfigs[vault.ProviderName].(vault.Config),
			},
			wantedContainers: []corev1.Container{
				{
					Name:         "MyContainer",
					Image:        "myimage",
					Command:      []string{"/bank-vaults/secret-init"},
					Args:         []string{"/bin/bash"},
					VolumeMounts: []corev1.VolumeMount{{Name: "secret-init", MountPath: "/bank-vaults/"}},
					Env: []corev1.EnvVar{
						{Name: "myvar", Value: "scheme://${vault:secret/data/account#username}:${vault:secret/data/account#password}@127.0.0.1:8080"},
						{Name: "VAULT_ADDR", Value: "addr"},
						{Name: "VAULT_SKIP_VERIFY", Value: "false"},
						{Name: "VAULT_AUTH_METHOD", Value: "jwt"},
						{Name: "VAULT_PATH", Value: "path"},
						{Name: "VAULT_ROLE", Value: "role"},
						{Name: "VAULT_IGNORE_MISSING_SECRETS", Value: "ignoreMissingSecrets"},
						{Name: "VAULT_PASSTHROUGH", Value: "vaultPassthrough"},
						{Name: "SECRET_INIT_JSON_LOG", Value: "enableJSONLog"},
						{Name: "VAULT_CLIENT_TIMEOUT", Value: "10s"},
					},
				},
			},
			mutated: true,
			wantErr: false,
		},
		{
			name: "Mutate will not change the containers log level if it was already set",
			fields: fields{
				k8sClient: fake.NewSimpleClientset(),
				registry: &MockRegistry{
					Image: v1.Config{},
				},
			},
			args: args{
				containers: []corev1.Container{
					{
						Name:    "MyContainer",
						Image:   "myimage",
						Command: []string{"/bin/bash"},
						Args:    nil,
						Env: []corev1.EnvVar{
							{
								Name:  "myvar",
								Value: "vault:secrets",
							},
							{
								Name:  "SECRET_INIT_LOG_LEVEL",
								Value: "info",
							},
						},
					},
				},
				webhookConfig: webhookConfig,
				SecretInitConfig: common.SecretInitConfig{
					JSONLog:  "enableJSONLog",
					LogLevel: "debug",
				},
				vaultConfig: vault.Config{
					Addr:                 "addr",
					SkipVerify:           false,
					Path:                 "path",
					Role:                 "role",
					AuthMethod:           "jwt",
					IgnoreMissingSecrets: "ignoreMissingSecrets",
					Passthrough:          "vaultPassthrough",
					ClientTimeout:        10 * time.Second,
				},
			},
			wantedContainers: []corev1.Container{
				{
					Name:         "MyContainer",
					Image:        "myimage",
					Command:      []string{"/bank-vaults/secret-init"},
					Args:         []string{"/bin/bash"},
					VolumeMounts: []corev1.VolumeMount{{Name: "secret-init", MountPath: "/bank-vaults/"}},
					Env: []corev1.EnvVar{
						{Name: "myvar", Value: "vault:secrets"},
						{Name: "SECRET_INIT_LOG_LEVEL", Value: "info"},
						{Name: "VAULT_ADDR", Value: "addr"},
						{Name: "VAULT_SKIP_VERIFY", Value: "false"},
						{Name: "VAULT_AUTH_METHOD", Value: "jwt"},
						{Name: "VAULT_PATH", Value: "path"},
						{Name: "VAULT_ROLE", Value: "role"},
						{Name: "VAULT_IGNORE_MISSING_SECRETS", Value: "ignoreMissingSecrets"},
						{Name: "VAULT_PASSTHROUGH", Value: "vaultPassthrough"},
						{Name: "SECRET_INIT_JSON_LOG", Value: "enableJSONLog"},
						{Name: "VAULT_CLIENT_TIMEOUT", Value: "10s"},
					},
				},
			},
			mutated: true,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		ttp := tt
		t.Run(ttp.name, func(t *testing.T) {
			mw := &MutatingWebhook{
				k8sClient: ttp.fields.k8sClient,
				registry:  ttp.fields.registry,
				logger:    slog.Default(),
			}

			currentlyUsedProvider = vault.ProviderName

			got, err := mw.mutateContainers(context.Background(), ttp.args.containers, ttp.args.podSpec, ttp.args.webhookConfig, ttp.args.SecretInitConfig, ttp.args.vaultConfig)
			if (err != nil) != ttp.wantErr {
				t.Errorf("MutatingWebhook.mutateContainers() error = %v, wantErr %v", err, ttp.wantErr)
				return
			}

			if got != ttp.mutated {
				t.Errorf("MutatingWebhook.mutateContainers() = %v, want %v", got, ttp.mutated)
			}

			if !cmp.Equal(ttp.args.containers, ttp.wantedContainers) {
				t.Errorf("MutatingWebhook.mutateContainers() = diff %v", cmp.Diff(ttp.args.containers, ttp.wantedContainers))
			}
		})
	}
}

func Test_mutatingWebhook_mutatePod(t *testing.T) {
	type fields struct {
		k8sClient kubernetes.Interface
		registry  ImageRegistry
	}
	type args struct {
		pod              *corev1.Pod
		webhookConfig    common.Config
		secretInitConfig common.SecretInitConfig
	}

	defaultMode := int32(420)

	baseSecurityContext := &corev1.SecurityContext{
		RunAsUser:                &webhookConfig.RunAsUser,
		RunAsGroup:               &webhookConfig.RunAsGroup,
		RunAsNonRoot:             &webhookConfig.RunAsNonRoot,
		ReadOnlyRootFilesystem:   &webhookConfig.ReadOnlyRootFilesystem,
		AllowPrivilegeEscalation: &webhookConfig.PspAllowPrivilegeEscalation,
		Capabilities: &corev1.Capabilities{
			Add: []corev1.Capability{},
			Drop: []corev1.Capability{
				"ALL",
			},
		},
	}

	agentInitContainerSecurityContext := &corev1.SecurityContext{
		RunAsUser:                &webhookConfig.RunAsUser,
		RunAsGroup:               &webhookConfig.RunAsGroup,
		RunAsNonRoot:             &webhookConfig.RunAsNonRoot,
		ReadOnlyRootFilesystem:   &webhookConfig.ReadOnlyRootFilesystem,
		AllowPrivilegeEscalation: &webhookConfig.PspAllowPrivilegeEscalation,
		Capabilities: &corev1.Capabilities{
			Add: []corev1.Capability{
				"CHOWN",
				"SETFCAP",
				"SETGID",
				"SETPCAP",
				"SETUID",
			},
			Drop: []corev1.Capability{
				"ALL",
			},
		},
	}

	agentContainerSecurityContext := &corev1.SecurityContext{
		RunAsUser:                &webhookConfig.RunAsUser,
		RunAsGroup:               &webhookConfig.RunAsGroup,
		RunAsNonRoot:             &webhookConfig.RunAsNonRoot,
		ReadOnlyRootFilesystem:   &webhookConfig.ReadOnlyRootFilesystem,
		AllowPrivilegeEscalation: &webhookConfig.PspAllowPrivilegeEscalation,
		Capabilities: &corev1.Capabilities{
			Drop: []corev1.Capability{
				"ALL",
			},
			Add: []corev1.Capability{
				"CHOWN",
				"SETFCAP",
				"SETGID",
				"SETPCAP",
				"SETUID",
				"IPC_LOCK",
			},
		},
	}

	tests := []struct {
		name      string
		fields    fields
		args      args
		wantErr   bool
		wantedPod *corev1.Pod
	}{
		{
			name: "Will mutate pod with ct-configmap annotations",
			fields: fields{
				k8sClient: fake.NewSimpleClientset(),
				registry: &MockRegistry{
					Image: v1.Config{},
				},
			},
			args: args{
				pod: &corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							common.VaultConsulTemplateConfigmapAnnotation:  "config-map-test",
							common.VaultConfigfilePathAnnotation:           "/vault/secrets",
							common.VaultAddrAnnotation:                     "test",
							common.VaultSkipVerifyAnnotation:               "false",
							common.VaultConsulTemplateCPUAnnotation:        "50m",
							common.VaultConsulTemplateMemoryAnnotation:     "128Mi",
							common.VaultImageAnnotation:                    "hashicorp/vault:latest",
							common.VaultImagePullPolicyAnnotation:          "IfNotPresent",
							common.ServiceAccountTokenVolumeNameAnnotation: "/var/run/secrets/kubernetes.io/serviceaccount",
						},
					},
					Spec: corev1.PodSpec{
						Containers: []corev1.Container{
							{
								Name:    "MyContainer",
								Image:   "myimage",
								Command: []string{"/bin/bash"},
								Args:    nil,
								VolumeMounts: []corev1.VolumeMount{
									{
										MountPath: "/var/run/secrets/kubernetes.io/serviceaccount",
									},
								},
							},
						},
					},
				},
				webhookConfig: common.Config{
					RunAsNonRoot: true,
					RunAsUser:    int64(1000),
					RunAsGroup:   int64(1000),
				},
				secretInitConfig: common.SecretInitConfig{
					CPURequest:    resource.MustParse("50m"),
					MemoryRequest: resource.MustParse("64Mi"),
					CPULimit:      resource.MustParse("250m"),
					MemoryLimit:   resource.MustParse("64Mi"),
				},
			},
			wantedPod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						common.VaultConsulTemplateConfigmapAnnotation:  "config-map-test",
						common.VaultConfigfilePathAnnotation:           "/vault/secrets",
						common.VaultAddrAnnotation:                     "test",
						common.VaultSkipVerifyAnnotation:               "false",
						common.VaultConsulTemplateCPUAnnotation:        "50m",
						common.VaultConsulTemplateMemoryAnnotation:     "128Mi",
						common.VaultImageAnnotation:                    "hashicorp/vault:latest",
						common.VaultImagePullPolicyAnnotation:          "IfNotPresent",
						common.ServiceAccountTokenVolumeNameAnnotation: "/var/run/secrets/kubernetes.io/serviceaccount",
					},
				},
				Spec: corev1.PodSpec{
					InitContainers: []corev1.Container{
						{
							Name:            "vault-agent",
							Image:           "hashicorp/vault:latest",
							Command:         []string{"vault", "agent", "-config=/vault/agent/config.hcl", "-exit-after-auth"},
							ImagePullPolicy: "IfNotPresent",
							Env: []corev1.EnvVar{
								{
									Name:  "VAULT_ADDR",
									Value: "test",
								},
								{
									Name:  "VAULT_SKIP_VERIFY",
									Value: "false",
								},
							},
							Resources: corev1.ResourceRequirements{
								Limits: corev1.ResourceList{
									corev1.ResourceCPU:    resource.MustParse("250m"),
									corev1.ResourceMemory: resource.MustParse("64Mi"),
								},
								Requests: corev1.ResourceList{
									corev1.ResourceCPU:    resource.MustParse("50m"),
									corev1.ResourceMemory: resource.MustParse("64Mi"),
								},
							},
							SecurityContext: agentInitContainerSecurityContext,
							VolumeMounts: []corev1.VolumeMount{
								{
									Name:      "secret-init",
									MountPath: "/bank-vaults/",
								},
								{
									MountPath: "/var/run/secrets/kubernetes.io/serviceaccount",
								},
								{
									Name:      "vault-agent-config",
									MountPath: "/vault/agent/",
								},
							},
						},
					},
					Containers: []corev1.Container{
						{
							Name:  "consul-template",
							Image: "hashicorp/consul-template:0.32.0",
							Args:  []string{"-config", "/vault/ct-config/config.hcl"},
							Resources: corev1.ResourceRequirements{
								Limits: corev1.ResourceList{
									corev1.ResourceCPU:    resource.MustParse("50m"),
									corev1.ResourceMemory: resource.MustParse("128Mi"),
								},
							},
							Env: []corev1.EnvVar{
								{
									Name:  "VAULT_ADDR",
									Value: "test",
								},
								{
									Name:  "VAULT_SKIP_VERIFY",
									Value: "false",
								},
							},
							ImagePullPolicy: "IfNotPresent",
							SecurityContext: baseSecurityContext,
							VolumeMounts: []corev1.VolumeMount{
								{
									Name:      "secret-init",
									MountPath: "/bank-vaults/",
								},
								{
									Name:      "ct-secrets",
									MountPath: "/vault/secrets",
								},
								{
									Name:      "secret-init",
									MountPath: "/home/consul-template",
								},
								{
									Name:      "ct-configmap",
									ReadOnly:  true,
									MountPath: "/vault/ct-config/config.hcl",
									SubPath:   "config.hcl",
								},
							},
						},
						{
							Name:    "MyContainer",
							Image:   "myimage",
							Command: []string{"/bin/bash"},
							Args:    nil,
							VolumeMounts: []corev1.VolumeMount{
								{
									MountPath: "/var/run/secrets/kubernetes.io/serviceaccount",
								},
								{
									Name:      "ct-secrets",
									MountPath: "/vault/secrets",
								},
							},
						},
					},
					Volumes: []corev1.Volume{
						{
							Name: "secret-init",
							VolumeSource: corev1.VolumeSource{
								EmptyDir: &corev1.EmptyDirVolumeSource{
									Medium: corev1.StorageMediumMemory,
								},
							},
						},
						{
							Name: "vault-agent-config",
							VolumeSource: corev1.VolumeSource{
								ConfigMap: &corev1.ConfigMapVolumeSource{
									LocalObjectReference: corev1.LocalObjectReference{
										Name: "-vault-agent-config",
									},
								},
							},
						},
						{
							Name: "ct-secrets",
							VolumeSource: corev1.VolumeSource{
								EmptyDir: &corev1.EmptyDirVolumeSource{
									Medium: corev1.StorageMediumMemory,
								},
							},
						},
						{
							Name: "ct-configmap",
							VolumeSource: corev1.VolumeSource{
								ConfigMap: &corev1.ConfigMapVolumeSource{
									LocalObjectReference: corev1.LocalObjectReference{
										Name: "config-map-test",
									},
									Items: []corev1.KeyToPath{
										{
											Key:  "config.hcl",
											Path: "config.hcl",
										},
									},
									DefaultMode: &defaultMode,
								},
							},
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "Will mutate pod with ct-once annotations",
			fields: fields{
				k8sClient: fake.NewSimpleClientset(),
				registry: &MockRegistry{
					Image: v1.Config{},
				},
			},
			args: args{
				pod: &corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							common.VaultConsulTemplateConfigmapAnnotation:  "config-map-test",
							common.VaultConsulTemplateOnceAnnotation:       "true",
							common.VaultConfigfilePathAnnotation:           "/vault/secrets",
							common.VaultAddrAnnotation:                     "test",
							common.VaultSkipVerifyAnnotation:               "false",
							common.VaultConsulTemplateCPUAnnotation:        "50m",
							common.VaultConsulTemplateMemoryAnnotation:     "128Mi",
							common.VaultImageAnnotation:                    "hashicorp/vault:latest",
							common.VaultImagePullPolicyAnnotation:          "IfNotPresent",
							common.ServiceAccountTokenVolumeNameAnnotation: "/var/run/secrets/kubernetes.io/serviceaccount",
						},
					},
					Spec: corev1.PodSpec{
						Containers: []corev1.Container{
							{
								Name:    "MyContainer",
								Image:   "myimage",
								Command: []string{"/bin/bash"},
								Args:    nil,
								VolumeMounts: []corev1.VolumeMount{
									{
										MountPath: "/var/run/secrets/kubernetes.io/serviceaccount",
									},
								},
							},
						},
					},
				},
				webhookConfig: common.Config{
					RunAsNonRoot: true,
					RunAsUser:    int64(1000),
					RunAsGroup:   int64(1000),
				},
				secretInitConfig: common.SecretInitConfig{
					CPURequest:    resource.MustParse("50m"),
					MemoryRequest: resource.MustParse("64Mi"),
					CPULimit:      resource.MustParse("250m"),
					MemoryLimit:   resource.MustParse("64Mi"),
				},
			},
			wantedPod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						common.VaultConsulTemplateConfigmapAnnotation:  "config-map-test",
						common.VaultConsulTemplateOnceAnnotation:       "true",
						common.VaultConfigfilePathAnnotation:           "/vault/secrets",
						common.VaultAddrAnnotation:                     "test",
						common.VaultSkipVerifyAnnotation:               "false",
						common.VaultConsulTemplateCPUAnnotation:        "50m",
						common.VaultConsulTemplateMemoryAnnotation:     "128Mi",
						common.VaultImageAnnotation:                    "hashicorp/vault:latest",
						common.VaultImagePullPolicyAnnotation:          "IfNotPresent",
						common.ServiceAccountTokenVolumeNameAnnotation: "/var/run/secrets/kubernetes.io/serviceaccount",
					},
				},
				Spec: corev1.PodSpec{
					InitContainers: []corev1.Container{
						{
							Name:            "vault-agent",
							Image:           "hashicorp/vault:latest",
							Command:         []string{"vault", "agent", "-config=/vault/agent/config.hcl", "-exit-after-auth"},
							ImagePullPolicy: "IfNotPresent",
							Env: []corev1.EnvVar{
								{
									Name:  "VAULT_ADDR",
									Value: "test",
								},
								{
									Name:  "VAULT_SKIP_VERIFY",
									Value: "false",
								},
							},
							Resources: corev1.ResourceRequirements{
								Limits: corev1.ResourceList{
									corev1.ResourceCPU:    resource.MustParse("250m"),
									corev1.ResourceMemory: resource.MustParse("64Mi"),
								},
								Requests: corev1.ResourceList{
									corev1.ResourceCPU:    resource.MustParse("50m"),
									corev1.ResourceMemory: resource.MustParse("64Mi"),
								},
							},
							SecurityContext: agentInitContainerSecurityContext,
							VolumeMounts: []corev1.VolumeMount{
								{
									Name:      "secret-init",
									MountPath: "/bank-vaults/",
								},
								{
									MountPath: "/var/run/secrets/kubernetes.io/serviceaccount",
								},
								{
									Name:      "vault-agent-config",
									MountPath: "/vault/agent/",
								},
							},
						},
						{
							Name:  "consul-template",
							Image: "hashicorp/consul-template:0.32.0",
							Args:  []string{"-config", "/vault/ct-config/config.hcl", "-once"},
							Resources: corev1.ResourceRequirements{
								Limits: corev1.ResourceList{
									corev1.ResourceCPU:    resource.MustParse("50m"),
									corev1.ResourceMemory: resource.MustParse("128Mi"),
								},
							},
							Env: []corev1.EnvVar{
								{
									Name:  "VAULT_ADDR",
									Value: "test",
								},
								{
									Name:  "VAULT_SKIP_VERIFY",
									Value: "false",
								},
							},
							ImagePullPolicy: "IfNotPresent",
							SecurityContext: baseSecurityContext,
							VolumeMounts: []corev1.VolumeMount{
								{
									Name:      "secret-init",
									MountPath: "/bank-vaults/",
								},
								{
									Name:      "ct-secrets",
									MountPath: "/vault/secrets",
								},
								{
									Name:      "secret-init",
									MountPath: "/home/consul-template",
								},
								{
									Name:      "ct-configmap",
									ReadOnly:  true,
									MountPath: "/vault/ct-config/config.hcl",
									SubPath:   "config.hcl",
								},
							},
						},
					},
					Containers: []corev1.Container{
						{
							Name:    "MyContainer",
							Image:   "myimage",
							Command: []string{"/bin/bash"},
							Args:    nil,
							VolumeMounts: []corev1.VolumeMount{
								{
									MountPath: "/var/run/secrets/kubernetes.io/serviceaccount",
								},
								{
									Name:      "ct-secrets",
									MountPath: "/vault/secrets",
								},
							},
						},
					},
					Volumes: []corev1.Volume{
						{
							Name: "secret-init",
							VolumeSource: corev1.VolumeSource{
								EmptyDir: &corev1.EmptyDirVolumeSource{
									Medium: corev1.StorageMediumMemory,
								},
							},
						},
						{
							Name: "vault-agent-config",
							VolumeSource: corev1.VolumeSource{
								ConfigMap: &corev1.ConfigMapVolumeSource{
									LocalObjectReference: corev1.LocalObjectReference{
										Name: "-vault-agent-config",
									},
								},
							},
						},
						{
							Name: "ct-secrets",
							VolumeSource: corev1.VolumeSource{
								EmptyDir: &corev1.EmptyDirVolumeSource{
									Medium: corev1.StorageMediumMemory,
								},
							},
						},
						{
							Name: "ct-configmap",
							VolumeSource: corev1.VolumeSource{
								ConfigMap: &corev1.ConfigMapVolumeSource{
									LocalObjectReference: corev1.LocalObjectReference{
										Name: "config-map-test",
									},
									Items: []corev1.KeyToPath{
										{
											Key:  "config.hcl",
											Path: "config.hcl",
										},
									},
									DefaultMode: &defaultMode,
								},
							},
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "Will mutate pod with agent-configmap annotations and envVariables",
			fields: fields{
				k8sClient: fake.NewSimpleClientset(),
				registry: &MockRegistry{
					Image: v1.Config{},
				},
			},
			args: args{
				pod: &corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							common.VaultAgentConfigmapAnnotation:           "config-map-test",
							common.VaultConfigfilePathAnnotation:           "/vault/secrets",
							common.VaultAddrAnnotation:                     "test",
							common.VaultSkipVerifyAnnotation:               "false",
							common.VaultAgentCPURequestAnnotation:          "200m",
							common.VaultAgentMemoryRequestAnnotation:       "256Mi",
							common.VaultAgentCPULimitAnnotation:            "500m",
							common.VaultAgentMemoryLimitAnnotation:         "384Mi",
							common.VaultImageAnnotation:                    "hashicorp/vault:latest",
							common.VaultImagePullPolicyAnnotation:          "IfNotPresent",
							common.ServiceAccountTokenVolumeNameAnnotation: "/var/run/secrets/kubernetes.io/serviceaccount",
							common.VaultAgentEnvVariablesAnnotation:        "[{\"Name\": \"SKIP_SETCAP\",\"Value\": \"1\"}]",
						},
					},
					Spec: corev1.PodSpec{
						Containers: []corev1.Container{
							{
								Name:    "MyContainer",
								Image:   "myimage",
								Command: []string{"/bin/bash"},
								Args:    nil,
								VolumeMounts: []corev1.VolumeMount{
									{
										MountPath: "/var/run/secrets/kubernetes.io/serviceaccount",
									},
								},
							},
						},
					},
				},
				webhookConfig: common.Config{
					RunAsNonRoot: true,
					RunAsUser:    int64(1000),
					RunAsGroup:   int64(1000),
				},
			},
			wantedPod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						common.VaultAgentConfigmapAnnotation:           "config-map-test",
						common.VaultConfigfilePathAnnotation:           "/vault/secrets",
						common.VaultAddrAnnotation:                     "test",
						common.VaultSkipVerifyAnnotation:               "false",
						common.VaultAgentCPURequestAnnotation:          "200m",
						common.VaultAgentMemoryRequestAnnotation:       "256Mi",
						common.VaultAgentCPULimitAnnotation:            "500m",
						common.VaultAgentMemoryLimitAnnotation:         "384Mi",
						common.VaultImageAnnotation:                    "hashicorp/vault:latest",
						common.VaultImagePullPolicyAnnotation:          "IfNotPresent",
						common.ServiceAccountTokenVolumeNameAnnotation: "/var/run/secrets/kubernetes.io/serviceaccount",
						common.VaultAgentEnvVariablesAnnotation:        "[{\"Name\": \"SKIP_SETCAP\",\"Value\": \"1\"}]",
					},
				},
				Spec: corev1.PodSpec{
					InitContainers: []corev1.Container{},
					Containers: []corev1.Container{
						{
							Name:            "vault-agent",
							Image:           "hashicorp/vault:latest",
							ImagePullPolicy: "IfNotPresent",
							Args:            []string{"agent", "-config", "/vault/config/config.hcl"},
							Resources: corev1.ResourceRequirements{
								Limits: corev1.ResourceList{
									corev1.ResourceCPU:    resource.MustParse("500m"),
									corev1.ResourceMemory: resource.MustParse("384Mi"),
								},
								Requests: corev1.ResourceList{
									corev1.ResourceCPU:    resource.MustParse("200m"),
									corev1.ResourceMemory: resource.MustParse("256Mi"),
								},
							},
							Env: []corev1.EnvVar{
								{
									Name:  "VAULT_ADDR",
									Value: "test",
								},
								{
									Name:  "VAULT_SKIP_VERIFY",
									Value: "false",
								},
								{
									Name:  "SKIP_SETCAP",
									Value: "1",
								},
							},
							SecurityContext: agentContainerSecurityContext,
							VolumeMounts: []corev1.VolumeMount{
								{
									Name:      "secret-init",
									MountPath: "/bank-vaults/",
								},
								{
									MountPath: "/var/run/secrets/kubernetes.io/serviceaccount",
								},
								{
									Name:      "agent-secrets",
									MountPath: "/vault/secrets",
								},
								{
									Name:      "agent-configmap",
									ReadOnly:  true,
									MountPath: "/vault/config/config.hcl",
									SubPath:   "config.hcl",
								},
							},
						},
						{
							Name:    "MyContainer",
							Image:   "myimage",
							Command: []string{"/bin/bash"},
							Args:    nil,
							VolumeMounts: []corev1.VolumeMount{
								{
									MountPath: "/var/run/secrets/kubernetes.io/serviceaccount",
								},
								{
									Name:      "agent-secrets",
									MountPath: "/vault/secrets",
								},
							},
						},
					},
					Volumes: []corev1.Volume{
						{
							Name: "secret-init",
							VolumeSource: corev1.VolumeSource{
								EmptyDir: &corev1.EmptyDirVolumeSource{
									Medium: corev1.StorageMediumMemory,
								},
							},
						},
						{
							Name: "agent-secrets",
							VolumeSource: corev1.VolumeSource{
								EmptyDir: &corev1.EmptyDirVolumeSource{
									Medium: corev1.StorageMediumMemory,
								},
							},
						},
						{
							Name: "agent-configmap",
							VolumeSource: corev1.VolumeSource{
								ConfigMap: &corev1.ConfigMapVolumeSource{
									LocalObjectReference: corev1.LocalObjectReference{
										Name: "config-map-test",
									},
									Items: []corev1.KeyToPath{
										{
											Key:  "config.hcl",
											Path: "config.hcl",
										},
									},
									DefaultMode: &defaultMode,
								},
							},
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "Will mutate pod with vault-ct-inject-in-initcontainers and ct-once annotations",
			fields: fields{
				k8sClient: fake.NewSimpleClientset(),
				registry: &MockRegistry{
					Image: v1.Config{},
				},
			},
			args: args{
				pod: &corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							common.VaultConsulTemplateConfigmapAnnotation:            "config-map-test",
							common.VaultConsulTemplateOnceAnnotation:                 "true",
							common.VaultConsulTemplateInjectInitcontainersAnnotation: "true",
							common.VaultConfigfilePathAnnotation:                     "/vault/secrets",
							common.VaultAddrAnnotation:                               "test",
							common.VaultSkipVerifyAnnotation:                         "false",
							common.VaultConsulTemplateCPUAnnotation:                  "50m",
							common.VaultConsulTemplateMemoryAnnotation:               "128Mi",
							common.VaultImageAnnotation:                              "hashicorp/vault:latest",
							common.VaultImagePullPolicyAnnotation:                    "IfNotPresent",
							common.ServiceAccountTokenVolumeNameAnnotation:           "/var/run/secrets/kubernetes.io/serviceaccount",
						},
					},
					Spec: corev1.PodSpec{
						InitContainers: []corev1.Container{
							{
								Name:    "MyInitContainer",
								Image:   "myInitimage",
								Command: []string{"/bin/bash"},
								Args:    nil,
								VolumeMounts: []corev1.VolumeMount{
									{
										MountPath: "/var/run/secrets/kubernetes.io/serviceaccount",
									},
								},
							},
						},
						Containers: []corev1.Container{
							{
								Name:    "MyContainer",
								Image:   "myimage",
								Command: []string{"/bin/bash"},
								Args:    nil,
								VolumeMounts: []corev1.VolumeMount{
									{
										MountPath: "/var/run/secrets/kubernetes.io/serviceaccount",
									},
								},
							},
						},
					},
				},
				webhookConfig: common.Config{
					RunAsNonRoot: true,
					RunAsUser:    int64(1000),
					RunAsGroup:   int64(1000),
				},
				secretInitConfig: common.SecretInitConfig{
					CPURequest:    resource.MustParse("50m"),
					MemoryRequest: resource.MustParse("64Mi"),
					CPULimit:      resource.MustParse("250m"),
					MemoryLimit:   resource.MustParse("64Mi"),
				},
			},
			wantedPod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						common.VaultConsulTemplateConfigmapAnnotation:            "config-map-test",
						common.VaultConsulTemplateOnceAnnotation:                 "true",
						common.VaultConsulTemplateInjectInitcontainersAnnotation: "true",
						common.VaultConfigfilePathAnnotation:                     "/vault/secrets",
						common.VaultAddrAnnotation:                               "test",
						common.VaultSkipVerifyAnnotation:                         "false",
						common.VaultConsulTemplateCPUAnnotation:                  "50m",
						common.VaultConsulTemplateMemoryAnnotation:               "128Mi",
						common.VaultImageAnnotation:                              "hashicorp/vault:latest",
						common.VaultImagePullPolicyAnnotation:                    "IfNotPresent",
						common.ServiceAccountTokenVolumeNameAnnotation:           "/var/run/secrets/kubernetes.io/serviceaccount",
					},
				},
				Spec: corev1.PodSpec{
					InitContainers: []corev1.Container{
						{
							Name:            "vault-agent",
							Image:           "hashicorp/vault:latest",
							Command:         []string{"vault", "agent", "-config=/vault/agent/config.hcl", "-exit-after-auth"},
							ImagePullPolicy: "IfNotPresent",
							Env: []corev1.EnvVar{
								{
									Name:  "VAULT_ADDR",
									Value: "test",
								},
								{
									Name:  "VAULT_SKIP_VERIFY",
									Value: "false",
								},
							},
							Resources: corev1.ResourceRequirements{
								Limits: corev1.ResourceList{
									corev1.ResourceCPU:    resource.MustParse("250m"),
									corev1.ResourceMemory: resource.MustParse("64Mi"),
								},
								Requests: corev1.ResourceList{
									corev1.ResourceCPU:    resource.MustParse("50m"),
									corev1.ResourceMemory: resource.MustParse("64Mi"),
								},
							},
							SecurityContext: agentInitContainerSecurityContext,
							VolumeMounts: []corev1.VolumeMount{
								{
									Name:      "secret-init",
									MountPath: "/bank-vaults/",
								},
								{
									MountPath: "/var/run/secrets/kubernetes.io/serviceaccount",
								},
								{
									Name:      "vault-agent-config",
									MountPath: "/vault/agent/",
								},
							},
						},
						{
							Name:  "consul-template",
							Image: "hashicorp/consul-template:0.32.0",
							Args:  []string{"-config", "/vault/ct-config/config.hcl", "-once"},
							Resources: corev1.ResourceRequirements{
								Limits: corev1.ResourceList{
									corev1.ResourceCPU:    resource.MustParse("50m"),
									corev1.ResourceMemory: resource.MustParse("128Mi"),
								},
							},
							Env: []corev1.EnvVar{
								{
									Name:  "VAULT_ADDR",
									Value: "test",
								},
								{
									Name:  "VAULT_SKIP_VERIFY",
									Value: "false",
								},
							},
							ImagePullPolicy: "IfNotPresent",
							SecurityContext: baseSecurityContext,
							VolumeMounts: []corev1.VolumeMount{
								{
									Name:      "secret-init",
									MountPath: "/bank-vaults/",
								},
								{
									Name:      "ct-secrets",
									MountPath: "/vault/secrets",
								},
								{
									Name:      "secret-init",
									MountPath: "/home/consul-template",
								},
								{
									Name:      "ct-configmap",
									ReadOnly:  true,
									MountPath: "/vault/ct-config/config.hcl",
									SubPath:   "config.hcl",
								},
							},
						},
						{
							Name:    "MyInitContainer",
							Image:   "myInitimage",
							Command: []string{"/bin/bash"},
							Args:    nil,
							VolumeMounts: []corev1.VolumeMount{
								{
									MountPath: "/var/run/secrets/kubernetes.io/serviceaccount",
								},
								{Name: "ct-secrets", MountPath: "/vault/secrets"},
							},
						},
					},
					Containers: []corev1.Container{
						{
							Name:    "MyContainer",
							Image:   "myimage",
							Command: []string{"/bin/bash"},
							Args:    nil,
							VolumeMounts: []corev1.VolumeMount{
								{
									MountPath: "/var/run/secrets/kubernetes.io/serviceaccount",
								},
								{
									Name:      "ct-secrets",
									MountPath: "/vault/secrets",
								},
							},
						},
					},
					Volumes: []corev1.Volume{
						{
							Name: "secret-init",
							VolumeSource: corev1.VolumeSource{
								EmptyDir: &corev1.EmptyDirVolumeSource{
									Medium: corev1.StorageMediumMemory,
								},
							},
						},
						{
							Name: "vault-agent-config",
							VolumeSource: corev1.VolumeSource{
								ConfigMap: &corev1.ConfigMapVolumeSource{
									LocalObjectReference: corev1.LocalObjectReference{
										Name: "-vault-agent-config",
									},
								},
							},
						},
						{
							Name: "ct-secrets",
							VolumeSource: corev1.VolumeSource{
								EmptyDir: &corev1.EmptyDirVolumeSource{
									Medium: corev1.StorageMediumMemory,
								},
							},
						},
						{
							Name: "ct-configmap",
							VolumeSource: corev1.VolumeSource{
								ConfigMap: &corev1.ConfigMapVolumeSource{
									LocalObjectReference: corev1.LocalObjectReference{
										Name: "config-map-test",
									},
									Items: []corev1.KeyToPath{
										{
											Key:  "config.hcl",
											Path: "config.hcl",
										},
									},
									DefaultMode: &defaultMode,
								},
							},
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "Will mutate pod with vault-ct-inject-in-initcontainers and without ct-once annotations",
			fields: fields{
				k8sClient: fake.NewSimpleClientset(),
				registry: &MockRegistry{
					Image: v1.Config{},
				},
			},
			args: args{
				pod: &corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							common.VaultConsulTemplateConfigmapAnnotation:            "config-map-test",
							common.VaultConsulTemplateInjectInitcontainersAnnotation: "true",
							common.VaultConfigfilePathAnnotation:                     "/vault/secrets",
							common.VaultAddrAnnotation:                               "test",
							common.VaultSkipVerifyAnnotation:                         "false",
							common.VaultConsulTemplateCPUAnnotation:                  "50m",
							common.VaultConsulTemplateMemoryAnnotation:               "128Mi",
							common.VaultImageAnnotation:                              "hashicorp/vault:latest",
							common.VaultImagePullPolicyAnnotation:                    "IfNotPresent",
							common.ServiceAccountTokenVolumeNameAnnotation:           "/var/run/secrets/vault",
						},
					},
					Spec: corev1.PodSpec{
						InitContainers: []corev1.Container{
							{
								Name:    "MyInitContainer",
								Image:   "myInitimage",
								Command: []string{"/bin/bash"},
								Args:    nil,
								VolumeMounts: []corev1.VolumeMount{
									{
										MountPath: "/var/run/secrets/vault",
									},
								},
							},
						},
						Containers: []corev1.Container{
							{
								Name:    "MyContainer",
								Image:   "myimage",
								Command: []string{"/bin/bash"},
								Args:    nil,
								VolumeMounts: []corev1.VolumeMount{
									{
										MountPath: "/var/run/secrets/vault",
									},
								},
							},
						},
					},
				},
				webhookConfig: common.Config{
					RunAsNonRoot: true,
					RunAsUser:    int64(1000),
					RunAsGroup:   int64(1000),
				},
				secretInitConfig: common.SecretInitConfig{
					CPURequest:    resource.MustParse("50m"),
					MemoryRequest: resource.MustParse("64Mi"),
					CPULimit:      resource.MustParse("250m"),
					MemoryLimit:   resource.MustParse("64Mi"),
				},
			},
			wantedPod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						common.VaultConsulTemplateConfigmapAnnotation:            "config-map-test",
						common.VaultConsulTemplateInjectInitcontainersAnnotation: "true",
						common.VaultConfigfilePathAnnotation:                     "/vault/secrets",
						common.VaultAddrAnnotation:                               "test",
						common.VaultSkipVerifyAnnotation:                         "false",
						common.VaultConsulTemplateCPUAnnotation:                  "50m",
						common.VaultConsulTemplateMemoryAnnotation:               "128Mi",
						common.VaultImageAnnotation:                              "hashicorp/vault:latest",
						common.VaultImagePullPolicyAnnotation:                    "IfNotPresent",
						common.ServiceAccountTokenVolumeNameAnnotation:           "/var/run/secrets/vault",
					},
				},
				Spec: corev1.PodSpec{
					InitContainers: []corev1.Container{
						{
							Name:            "vault-agent",
							Image:           "hashicorp/vault:latest",
							Command:         []string{"vault", "agent", "-config=/vault/agent/config.hcl", "-exit-after-auth"},
							ImagePullPolicy: "IfNotPresent",
							Env: []corev1.EnvVar{
								{
									Name:  "VAULT_ADDR",
									Value: "test",
								},
								{
									Name:  "VAULT_SKIP_VERIFY",
									Value: "false",
								},
							},
							Resources: corev1.ResourceRequirements{
								Limits: corev1.ResourceList{
									corev1.ResourceCPU:    resource.MustParse("250m"),
									corev1.ResourceMemory: resource.MustParse("64Mi"),
								},
								Requests: corev1.ResourceList{
									corev1.ResourceCPU:    resource.MustParse("50m"),
									corev1.ResourceMemory: resource.MustParse("64Mi"),
								},
							},
							SecurityContext: agentInitContainerSecurityContext,
							VolumeMounts: []corev1.VolumeMount{
								{
									Name:      "secret-init",
									MountPath: "/bank-vaults/",
								},
								{
									MountPath: "/var/run/secrets/vault",
								},
								{
									Name:      "vault-agent-config",
									MountPath: "/vault/agent/",
								},
							},
						},
						{
							Name:    "MyInitContainer",
							Image:   "myInitimage",
							Command: []string{"/bin/bash"},
							Args:    nil,
							VolumeMounts: []corev1.VolumeMount{
								{
									MountPath: "/var/run/secrets/vault",
								},
							},
						},
					},
					Containers: []corev1.Container{
						{
							Name:  "consul-template",
							Image: "hashicorp/consul-template:0.32.0",
							Args:  []string{"-config", "/vault/ct-config/config.hcl"},
							Resources: corev1.ResourceRequirements{
								Limits: corev1.ResourceList{
									corev1.ResourceCPU:    resource.MustParse("50m"),
									corev1.ResourceMemory: resource.MustParse("128Mi"),
								},
							},
							Env: []corev1.EnvVar{
								{
									Name:  "VAULT_ADDR",
									Value: "test",
								},
								{
									Name:  "VAULT_SKIP_VERIFY",
									Value: "false",
								},
							},
							ImagePullPolicy: "IfNotPresent",
							SecurityContext: baseSecurityContext,
							VolumeMounts: []corev1.VolumeMount{
								{
									Name:      "secret-init",
									MountPath: "/bank-vaults/",
								},
								{
									Name:      "ct-secrets",
									MountPath: "/vault/secrets",
								},
								{
									Name:      "secret-init",
									MountPath: "/home/consul-template",
								},
								{
									Name:      "ct-configmap",
									ReadOnly:  true,
									MountPath: "/vault/ct-config/config.hcl",
									SubPath:   "config.hcl",
								},
							},
						},
						{
							Name:    "MyContainer",
							Image:   "myimage",
							Command: []string{"/bin/bash"},
							Args:    nil,
							VolumeMounts: []corev1.VolumeMount{
								{
									MountPath: "/var/run/secrets/vault",
								},
								{
									Name:      "ct-secrets",
									MountPath: "/vault/secrets",
								},
							},
						},
					},
					Volumes: []corev1.Volume{
						{
							Name: "secret-init",
							VolumeSource: corev1.VolumeSource{
								EmptyDir: &corev1.EmptyDirVolumeSource{
									Medium: corev1.StorageMediumMemory,
								},
							},
						},
						{
							Name: "vault-agent-config",
							VolumeSource: corev1.VolumeSource{
								ConfigMap: &corev1.ConfigMapVolumeSource{
									LocalObjectReference: corev1.LocalObjectReference{
										Name: "-vault-agent-config",
									},
								},
							},
						},
						{
							Name: "ct-secrets",
							VolumeSource: corev1.VolumeSource{
								EmptyDir: &corev1.EmptyDirVolumeSource{
									Medium: corev1.StorageMediumMemory,
								},
							},
						},
						{
							Name: "ct-configmap",
							VolumeSource: corev1.VolumeSource{
								ConfigMap: &corev1.ConfigMapVolumeSource{
									LocalObjectReference: corev1.LocalObjectReference{
										Name: "config-map-test",
									},
									Items: []corev1.KeyToPath{
										{
											Key:  "config.hcl",
											Path: "config.hcl",
										},
									},
									DefaultMode: &defaultMode,
								},
							},
						},
					},
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		ttp := tt
		t.Run(ttp.name, func(t *testing.T) {
			mw := &MutatingWebhook{
				k8sClient: ttp.fields.k8sClient,
				registry:  ttp.fields.registry,
				logger:    slog.Default(),
			}

			admissionReview := &model.AdmissionReview{}

			providerConfigs, err := parseProviderConfigs(ttp.args.pod, admissionReview, []string{vault.ProviderName})
			if (err != nil) != ttp.wantErr {
				t.Errorf("parseProviderConfigs() error = %v, wantErr %v", err, ttp.wantErr)
				return
			}

			err = mw.MutatePod(context.Background(), ttp.args.pod, ttp.args.webhookConfig, ttp.args.secretInitConfig, false, providerConfigs)
			if (err != nil) != ttp.wantErr {
				t.Errorf("MutatingWebhook.MutatePod() error = %v, wantErr %v", err, ttp.wantErr)
				return
			}

			if !cmp.Equal(ttp.args.pod, ttp.wantedPod) {
				t.Errorf("MutatingWebhook.MutatePod() = diff %v", cmp.Diff(ttp.args.pod, ttp.wantedPod))
			}
		})
	}
}
