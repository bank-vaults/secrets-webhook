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

package bao

import (
	"context"
	"log/slog"
	"testing"
	"time"

	cmp "github.com/google/go-cmp/cmp"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/client-go/kubernetes"
	fake "k8s.io/client-go/kubernetes/fake"

	appCommon "github.com/bank-vaults/secrets-webhook/pkg/common"
	"github.com/bank-vaults/secrets-webhook/pkg/registry"
)

var webhookConfig = appCommon.Config{
	RunAsNonRoot: true,
	RunAsUser:    int64(1000),
	RunAsGroup:   int64(1000),
}

var secretInitConfig = appCommon.SecretInitConfig{
	JSONLog: "enableJSONLog",
}

var baoConfig = Config{
	Addr:                 "addr",
	SkipVerify:           false,
	Path:                 "path",
	Role:                 "role",
	AuthMethod:           "jwt",
	IgnoreMissingSecrets: "ignoreMissingSecrets",
	Passthrough:          "baoPassthrough",
	ClientTimeout:        10 * time.Second,
}

type MockRegistry struct {
	Image v1.Config
}

func (r *MockRegistry) GetImageConfig(_ context.Context, _ kubernetes.Interface, _ string, _ bool, _ *corev1.Container, _ *corev1.PodSpec) (*v1.Config, error) {
	return &r.Image, nil
}

func Test_mutator_mutateContainers(t *testing.T) {
	baoConfigEnvFrom := baoConfig
	baoConfigEnvFrom.FromPath = "secrets/application"

	type fields struct {
		k8sClient kubernetes.Interface
		registry  registry.ImageRegistry
	}
	type args struct {
		containers       []corev1.Container
		podSpec          *corev1.PodSpec
		webhookConfig    appCommon.Config
		SecretInitConfig appCommon.SecretInitConfig
		baoConfig        Config
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
								Value: "bao:secrets",
							},
						},
					},
				},
				webhookConfig:    webhookConfig,
				SecretInitConfig: secretInitConfig,
				baoConfig:        baoConfig,
			},
			wantedContainers: []corev1.Container{
				{
					Name:         "MyContainer",
					Image:        "myimage",
					Command:      []string{"/bao/secret-init"},
					Args:         []string{"/bin/bash"},
					VolumeMounts: []corev1.VolumeMount{{Name: "secret-init", MountPath: "/bao/"}},
					Env: []corev1.EnvVar{
						{Name: "myvar", Value: "bao:secrets"},
						{Name: "BAO_ADDR", Value: "addr"},
						{Name: "BAO_SKIP_VERIFY", Value: "false"},
						{Name: "BAO_AUTH_METHOD", Value: "jwt"},
						{Name: "BAO_PATH", Value: "path"},
						{Name: "BAO_ROLE", Value: "role"},
						{Name: "BAO_IGNORE_MISSING_SECRETS", Value: "ignoreMissingSecrets"},
						{Name: "BAO_PASSTHROUGH", Value: "baoPassthrough"},
						{Name: "SECRET_INIT_JSON_LOG", Value: "enableJSONLog"},
						{Name: "BAO_CLIENT_TIMEOUT", Value: "10s"},
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
								Value: ">>bao:secrets",
							},
						},
					},
				},
				webhookConfig:    webhookConfig,
				SecretInitConfig: secretInitConfig,
				baoConfig:        baoConfig,
			},
			wantedContainers: []corev1.Container{
				{
					Name:         "MyContainer",
					Image:        "myimage",
					Command:      []string{"/bao/secret-init"},
					Args:         []string{"/bin/bash"},
					VolumeMounts: []corev1.VolumeMount{{Name: "secret-init", MountPath: "/bao/"}},
					Env: []corev1.EnvVar{
						{Name: "myvar", Value: ">>bao:secrets"},
						{Name: "BAO_ADDR", Value: "addr"},
						{Name: "BAO_SKIP_VERIFY", Value: "false"},
						{Name: "BAO_AUTH_METHOD", Value: "jwt"},
						{Name: "BAO_PATH", Value: "path"},
						{Name: "BAO_ROLE", Value: "role"},
						{Name: "BAO_IGNORE_MISSING_SECRETS", Value: "ignoreMissingSecrets"},
						{Name: "BAO_PASSTHROUGH", Value: "baoPassthrough"},
						{Name: "SECRET_INIT_JSON_LOG", Value: "enableJSONLog"},
						{Name: "BAO_CLIENT_TIMEOUT", Value: "10s"},
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
								Value: ">>bao:secrets",
							},
						},
					},
				},
				webhookConfig:    webhookConfig,
				SecretInitConfig: secretInitConfig,
				baoConfig:        baoConfig,
			},
			wantedContainers: []corev1.Container{
				{
					Name:         "MyContainer",
					Image:        "myimage",
					Command:      []string{"/bao/secret-init"},
					Args:         []string{"myEntryPoint"},
					VolumeMounts: []corev1.VolumeMount{{Name: "secret-init", MountPath: "/bao/"}},
					Env: []corev1.EnvVar{
						{Name: "myvar", Value: ">>bao:secrets"},
						{Name: "BAO_ADDR", Value: "addr"},
						{Name: "BAO_SKIP_VERIFY", Value: "false"},
						{Name: "BAO_AUTH_METHOD", Value: "jwt"},
						{Name: "BAO_PATH", Value: "path"},
						{Name: "BAO_ROLE", Value: "role"},
						{Name: "BAO_IGNORE_MISSING_SECRETS", Value: "ignoreMissingSecrets"},
						{Name: "BAO_PASSTHROUGH", Value: "baoPassthrough"},
						{Name: "SECRET_INIT_JSON_LOG", Value: "enableJSONLog"},
						{Name: "BAO_CLIENT_TIMEOUT", Value: "10s"},
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
						ReadinessProbe: &corev1.Probe{
							ProbeHandler: corev1.ProbeHandler{
								Exec: &corev1.ExecAction{
									Command: []string{"/bin/bash"},
								},
							},
						},
						StartupProbe: &corev1.Probe{
							ProbeHandler: corev1.ProbeHandler{
								Exec: &corev1.ExecAction{
									Command: []string{"/bin/bash"},
								},
							},
						},
						Env: []corev1.EnvVar{
							{
								Name:  "myvar",
								Value: "bao:secrets",
							},
						},
					},
				},
				webhookConfig: appCommon.Config{
					MutateProbes: true,
				},
				SecretInitConfig: appCommon.SecretInitConfig{},
				baoConfig:        Config{},
			},
			wantedContainers: []corev1.Container{
				{
					Name:         "MyContainer",
					Image:        "myimage",
					Command:      []string{"/bao/secret-init"},
					Args:         []string{"/bin/bash"},
					VolumeMounts: []corev1.VolumeMount{{Name: "secret-init", MountPath: "/bao/"}},
					LivenessProbe: &corev1.Probe{
						ProbeHandler: corev1.ProbeHandler{
							Exec: &corev1.ExecAction{
								Command: []string{"/bao/secret-init", "/bin/bash"},
							},
						},
					},
					ReadinessProbe: &corev1.Probe{
						ProbeHandler: corev1.ProbeHandler{
							Exec: &corev1.ExecAction{
								Command: []string{"/bao/secret-init", "/bin/bash"},
							},
						},
					},
					StartupProbe: &corev1.Probe{
						ProbeHandler: corev1.ProbeHandler{
							Exec: &corev1.ExecAction{
								Command: []string{"/bao/secret-init", "/bin/bash"},
							},
						},
					},
					Env: []corev1.EnvVar{
						{Name: "myvar", Value: "bao:secrets"},
						{Name: "BAO_ADDR", Value: ""},
						{Name: "BAO_SKIP_VERIFY", Value: "false"},
						{Name: "BAO_AUTH_METHOD", Value: ""},
						{Name: "BAO_PATH", Value: ""},
						{Name: "BAO_ROLE", Value: ""},
						{Name: "BAO_IGNORE_MISSING_SECRETS", Value: ""},
						{Name: "BAO_PASSTHROUGH", Value: ""},
						{Name: "SECRET_INIT_JSON_LOG", Value: ""},
						{Name: "BAO_CLIENT_TIMEOUT", Value: "0s"},
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
								Value: ">>bao:secrets",
							},
						},
					},
				},
				webhookConfig:    webhookConfig,
				SecretInitConfig: secretInitConfig,
				baoConfig:        baoConfig,
			},
			wantedContainers: []corev1.Container{
				{
					Name:         "MyContainer",
					Image:        "myimage",
					Command:      []string{"/bao/secret-init"},
					Args:         []string{"myCmd"},
					VolumeMounts: []corev1.VolumeMount{{Name: "secret-init", MountPath: "/bao/"}},
					Env: []corev1.EnvVar{
						{Name: "myvar", Value: ">>bao:secrets"},
						{Name: "BAO_ADDR", Value: "addr"},
						{Name: "BAO_SKIP_VERIFY", Value: "false"},
						{Name: "BAO_AUTH_METHOD", Value: "jwt"},
						{Name: "BAO_PATH", Value: "path"},
						{Name: "BAO_ROLE", Value: "role"},
						{Name: "BAO_IGNORE_MISSING_SECRETS", Value: "ignoreMissingSecrets"},
						{Name: "BAO_PASSTHROUGH", Value: "baoPassthrough"},
						{Name: "SECRET_INIT_JSON_LOG", Value: "enableJSONLog"},
						{Name: "BAO_CLIENT_TIMEOUT", Value: "10s"},
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
				baoConfig:        baoConfig,
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
								Value: "bao:secrets",
							},
						},
					},
				},
				webhookConfig:    webhookConfig,
				SecretInitConfig: secretInitConfig,
				baoConfig:        baoConfigEnvFrom,
			},
			wantedContainers: []corev1.Container{
				{
					Name:         "MyContainer",
					Image:        "myimage",
					Command:      []string{"/bao/secret-init"},
					Args:         []string{"/bin/bash"},
					VolumeMounts: []corev1.VolumeMount{{Name: "secret-init", MountPath: "/bao/"}},
					Env: []corev1.EnvVar{
						{Name: "myvar", Value: "bao:secrets"},
						{Name: "BAO_ADDR", Value: "addr"},
						{Name: "BAO_SKIP_VERIFY", Value: "false"},
						{Name: "BAO_AUTH_METHOD", Value: "jwt"},
						{Name: "BAO_PATH", Value: "path"},
						{Name: "BAO_ROLE", Value: "role"},
						{Name: "BAO_IGNORE_MISSING_SECRETS", Value: "ignoreMissingSecrets"},
						{Name: "BAO_PASSTHROUGH", Value: "baoPassthrough"},
						{Name: "SECRET_INIT_JSON_LOG", Value: "enableJSONLog"},
						{Name: "BAO_CLIENT_TIMEOUT", Value: "10s"},
						{Name: "BAO_FROM_PATH", Value: "secrets/application"},
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
								Value: "scheme://${bao:secret/data/account#username}:${bao:secret/data/account#password}@127.0.0.1:8080",
							},
						},
					},
				},
				webhookConfig:    webhookConfig,
				SecretInitConfig: secretInitConfig,
				baoConfig:        baoConfig,
			},
			wantedContainers: []corev1.Container{
				{
					Name:         "MyContainer",
					Image:        "myimage",
					Command:      []string{"/bao/secret-init"},
					Args:         []string{"/bin/bash"},
					VolumeMounts: []corev1.VolumeMount{{Name: "secret-init", MountPath: "/bao/"}},
					Env: []corev1.EnvVar{
						{Name: "myvar", Value: "scheme://${bao:secret/data/account#username}:${bao:secret/data/account#password}@127.0.0.1:8080"},
						{Name: "BAO_ADDR", Value: "addr"},
						{Name: "BAO_SKIP_VERIFY", Value: "false"},
						{Name: "BAO_AUTH_METHOD", Value: "jwt"},
						{Name: "BAO_PATH", Value: "path"},
						{Name: "BAO_ROLE", Value: "role"},
						{Name: "BAO_IGNORE_MISSING_SECRETS", Value: "ignoreMissingSecrets"},
						{Name: "BAO_PASSTHROUGH", Value: "baoPassthrough"},
						{Name: "SECRET_INIT_JSON_LOG", Value: "enableJSONLog"},
						{Name: "BAO_CLIENT_TIMEOUT", Value: "10s"},
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
								Value: "bao:secrets",
							},
							{
								Name:  "SECRET_INIT_LOG_LEVEL",
								Value: "info",
							},
						},
					},
				},
				webhookConfig: webhookConfig,
				SecretInitConfig: appCommon.SecretInitConfig{
					JSONLog:  "enableJSONLog",
					LogLevel: "debug",
				},
				baoConfig: Config{
					Addr:                 "addr",
					SkipVerify:           false,
					Path:                 "path",
					Role:                 "role",
					AuthMethod:           "jwt",
					IgnoreMissingSecrets: "ignoreMissingSecrets",
					Passthrough:          "baoPassthrough",
					ClientTimeout:        10 * time.Second,
				},
			},
			wantedContainers: []corev1.Container{
				{
					Name:         "MyContainer",
					Image:        "myimage",
					Command:      []string{"/bao/secret-init"},
					Args:         []string{"/bin/bash"},
					VolumeMounts: []corev1.VolumeMount{{Name: "secret-init", MountPath: "/bao/"}},
					Env: []corev1.EnvVar{
						{Name: "myvar", Value: "bao:secrets"},
						{Name: "SECRET_INIT_LOG_LEVEL", Value: "info"},
						{Name: "BAO_ADDR", Value: "addr"},
						{Name: "BAO_SKIP_VERIFY", Value: "false"},
						{Name: "BAO_AUTH_METHOD", Value: "jwt"},
						{Name: "BAO_PATH", Value: "path"},
						{Name: "BAO_ROLE", Value: "role"},
						{Name: "BAO_IGNORE_MISSING_SECRETS", Value: "ignoreMissingSecrets"},
						{Name: "BAO_PASSTHROUGH", Value: "baoPassthrough"},
						{Name: "SECRET_INIT_JSON_LOG", Value: "enableJSONLog"},
						{Name: "BAO_CLIENT_TIMEOUT", Value: "10s"},
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

			mutator := mutator{client: nil, config: &ttp.args.baoConfig, logger: slog.Default()}
			got, err := mutator.MutateContainers(context.Background(), ttp.args.containers, ttp.args.podSpec, ttp.args.webhookConfig, ttp.args.SecretInitConfig, ttp.fields.k8sClient, ttp.fields.registry)
			if (err != nil) != ttp.wantErr {
				t.Errorf("mutator.MutateContainers() error = %v, wantErr %v", err, ttp.wantErr)
				return
			}

			if got != ttp.mutated {
				t.Errorf("mutator.MutateContainers() = %v, want %v", got, ttp.mutated)
			}

			if !cmp.Equal(ttp.args.containers, ttp.wantedContainers) {
				t.Errorf("mutator.MutateContainers() = diff %v", cmp.Diff(ttp.args.containers, ttp.wantedContainers))
			}
		})
	}
}

func Test_mutator_mutatePod(t *testing.T) {
	type fields struct {
		k8sClient kubernetes.Interface
		registry  registry.ImageRegistry
	}
	type args struct {
		pod              *corev1.Pod
		webhookConfig    appCommon.Config
		secretInitConfig appCommon.SecretInitConfig
		baoConfig        Config
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
				webhookConfig: appCommon.Config{
					RunAsNonRoot: true,
					RunAsUser:    int64(1000),
					RunAsGroup:   int64(1000),
				},
				secretInitConfig: appCommon.SecretInitConfig{
					CPURequest:    resource.MustParse("50m"),
					MemoryRequest: resource.MustParse("64Mi"),
					CPULimit:      resource.MustParse("250m"),
					MemoryLimit:   resource.MustParse("64Mi"),
				},
				baoConfig: Config{
					CtConfigMap:                   "config-map-test",
					ConfigfilePath:                "/bao/secrets",
					Addr:                          "test",
					SkipVerify:                    false,
					CtCPU:                         resource.MustParse("50m"),
					CtMemory:                      resource.MustParse("128Mi"),
					AgentImage:                    "openbao/bao:latest",
					AgentImagePullPolicy:          "IfNotPresent",
					ServiceAccountTokenVolumeName: "/var/run/secrets/kubernetes.io/serviceaccount",
				},
			},
			wantedPod: &corev1.Pod{
				Spec: corev1.PodSpec{
					InitContainers: []corev1.Container{
						{
							Name:            "bao-agent",
							Image:           "openbao/bao:latest",
							Command:         []string{"bao", "agent", "-config=/bao/agent/config.hcl", "-exit-after-auth"},
							ImagePullPolicy: "IfNotPresent",
							Env: []corev1.EnvVar{
								{
									Name:  "BAO_ADDR",
									Value: "test",
								},
								{
									Name:  "BAO_SKIP_VERIFY",
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
									MountPath: "/bao/",
								},
								{
									MountPath: "/var/run/secrets/kubernetes.io/serviceaccount",
								},
								{
									Name:      "bao-agent-config",
									MountPath: "/bao/agent/",
								},
							},
						},
					},
					Containers: []corev1.Container{
						{
							Name: "consul-template",
							Args: []string{"-config", "/bao/ct-config/config.hcl"},
							Resources: corev1.ResourceRequirements{
								Limits: corev1.ResourceList{
									corev1.ResourceCPU:    resource.MustParse("50m"),
									corev1.ResourceMemory: resource.MustParse("128Mi"),
								},
							},
							Env: []corev1.EnvVar{
								{
									Name:  "BAO_ADDR",
									Value: "test",
								},
								{
									Name:  "BAO_SKIP_VERIFY",
									Value: "false",
								},
							},
							SecurityContext: baseSecurityContext,
							VolumeMounts: []corev1.VolumeMount{
								{
									Name:      "secret-init",
									MountPath: "/bao/",
								},
								{
									Name:      "ct-secrets",
									MountPath: "/bao/secrets",
								},
								{
									Name:      "secret-init",
									MountPath: "/home/consul-template",
								},
								{
									Name:      "ct-configmap",
									ReadOnly:  true,
									MountPath: "/bao/ct-config/config.hcl",
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
									MountPath: "/bao/secrets",
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
							Name: "bao-agent-config",
							VolumeSource: corev1.VolumeSource{
								ConfigMap: &corev1.ConfigMapVolumeSource{
									LocalObjectReference: corev1.LocalObjectReference{
										Name: "-bao-agent-config",
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
				webhookConfig: appCommon.Config{
					RunAsNonRoot: true,
					RunAsUser:    int64(1000),
					RunAsGroup:   int64(1000),
				},
				secretInitConfig: appCommon.SecretInitConfig{
					CPURequest:    resource.MustParse("50m"),
					MemoryRequest: resource.MustParse("64Mi"),
					CPULimit:      resource.MustParse("250m"),
					MemoryLimit:   resource.MustParse("64Mi"),
				},
				baoConfig: Config{
					CtConfigMap:                   "config-map-test",
					CtOnce:                        true,
					ConfigfilePath:                "/bao/secrets",
					Addr:                          "test",
					SkipVerify:                    false,
					CtCPU:                         resource.MustParse("50m"),
					CtMemory:                      resource.MustParse("128Mi"),
					AgentImage:                    "openbao/bao:latest",
					AgentImagePullPolicy:          "IfNotPresent",
					ServiceAccountTokenVolumeName: "/var/run/secrets/kubernetes.io/serviceaccount",
				},
			},
			wantedPod: &corev1.Pod{
				Spec: corev1.PodSpec{
					InitContainers: []corev1.Container{
						{
							Name:            "bao-agent",
							Image:           "openbao/bao:latest",
							Command:         []string{"bao", "agent", "-config=/bao/agent/config.hcl", "-exit-after-auth"},
							ImagePullPolicy: "IfNotPresent",
							Env: []corev1.EnvVar{
								{
									Name:  "BAO_ADDR",
									Value: "test",
								},
								{
									Name:  "BAO_SKIP_VERIFY",
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
									MountPath: "/bao/",
								},
								{
									MountPath: "/var/run/secrets/kubernetes.io/serviceaccount",
								},
								{
									Name:      "bao-agent-config",
									MountPath: "/bao/agent/",
								},
							},
						},
						{
							Name: "consul-template",
							Args: []string{"-config", "/bao/ct-config/config.hcl", "-once"},
							Resources: corev1.ResourceRequirements{
								Limits: corev1.ResourceList{
									corev1.ResourceCPU:    resource.MustParse("50m"),
									corev1.ResourceMemory: resource.MustParse("128Mi"),
								},
							},
							Env: []corev1.EnvVar{
								{
									Name:  "BAO_ADDR",
									Value: "test",
								},
								{
									Name:  "BAO_SKIP_VERIFY",
									Value: "false",
								},
							},
							SecurityContext: baseSecurityContext,
							VolumeMounts: []corev1.VolumeMount{
								{
									Name:      "secret-init",
									MountPath: "/bao/",
								},
								{
									Name:      "ct-secrets",
									MountPath: "/bao/secrets",
								},
								{
									Name:      "secret-init",
									MountPath: "/home/consul-template",
								},
								{
									Name:      "ct-configmap",
									ReadOnly:  true,
									MountPath: "/bao/ct-config/config.hcl",
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
									MountPath: "/bao/secrets",
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
							Name: "bao-agent-config",
							VolumeSource: corev1.VolumeSource{
								ConfigMap: &corev1.ConfigMapVolumeSource{
									LocalObjectReference: corev1.LocalObjectReference{
										Name: "-bao-agent-config",
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
				webhookConfig: appCommon.Config{
					RunAsNonRoot: true,
					RunAsUser:    int64(1000),
					RunAsGroup:   int64(1000),
				},
				baoConfig: Config{
					AgentConfigMap:                "config-map-test",
					ConfigfilePath:                "/bao/secrets",
					Addr:                          "test",
					SkipVerify:                    false,
					AgentCPURequest:               resource.MustParse("200m"),
					AgentMemoryRequest:            resource.MustParse("256Mi"),
					AgentCPULimit:                 resource.MustParse("500m"),
					AgentMemoryLimit:              resource.MustParse("384Mi"),
					AgentImage:                    "openbao/bao:latest",
					AgentImagePullPolicy:          "IfNotPresent",
					ServiceAccountTokenVolumeName: "/var/run/secrets/kubernetes.io/serviceaccount",
					AgentEnvVariables:             "[{\"Name\": \"SKIP_SETCAP\",\"Value\": \"1\"}]",
				},
			},
			wantedPod: &corev1.Pod{
				Spec: corev1.PodSpec{
					InitContainers: []corev1.Container{},
					Containers: []corev1.Container{
						{
							Name:            "bao-agent",
							Image:           "openbao/bao:latest",
							ImagePullPolicy: "IfNotPresent",
							Args:            []string{"agent", "-config", "/bao/config/config.hcl"},
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
									Name:  "BAO_ADDR",
									Value: "test",
								},
								{
									Name:  "BAO_SKIP_VERIFY",
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
									MountPath: "/bao/",
								},
								{
									MountPath: "/var/run/secrets/kubernetes.io/serviceaccount",
								},
								{
									Name:      "agent-secrets",
									MountPath: "/bao/secrets",
								},
								{
									Name:      "agent-configmap",
									ReadOnly:  true,
									MountPath: "/bao/config/config.hcl",
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
									MountPath: "/bao/secrets",
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
			name: "Will mutate pod with bao-ct-inject-in-initcontainers and ct-once annotations",
			fields: fields{
				k8sClient: fake.NewSimpleClientset(),
				registry: &MockRegistry{
					Image: v1.Config{},
				},
			},
			args: args{
				pod: &corev1.Pod{
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
				webhookConfig: appCommon.Config{
					RunAsNonRoot: true,
					RunAsUser:    int64(1000),
					RunAsGroup:   int64(1000),
				},
				secretInitConfig: appCommon.SecretInitConfig{
					CPURequest:    resource.MustParse("50m"),
					MemoryRequest: resource.MustParse("64Mi"),
					CPULimit:      resource.MustParse("250m"),
					MemoryLimit:   resource.MustParse("64Mi"),
				},
				baoConfig: Config{
					CtConfigMap:                   "config-map-test",
					CtOnce:                        true,
					CtInjectInInitcontainers:      true,
					ConfigfilePath:                "/bao/secrets",
					Addr:                          "test",
					SkipVerify:                    false,
					CtCPU:                         resource.MustParse("50m"),
					CtMemory:                      resource.MustParse("128Mi"),
					AgentImage:                    "openbao/bao:latest",
					AgentImagePullPolicy:          "IfNotPresent",
					ServiceAccountTokenVolumeName: "/var/run/secrets/kubernetes.io/serviceaccount",
				},
			},
			wantedPod: &corev1.Pod{
				Spec: corev1.PodSpec{
					InitContainers: []corev1.Container{
						{
							Name:            "bao-agent",
							Image:           "openbao/bao:latest",
							Command:         []string{"bao", "agent", "-config=/bao/agent/config.hcl", "-exit-after-auth"},
							ImagePullPolicy: "IfNotPresent",
							Env: []corev1.EnvVar{
								{
									Name:  "BAO_ADDR",
									Value: "test",
								},
								{
									Name:  "BAO_SKIP_VERIFY",
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
									MountPath: "/bao/",
								},
								{
									MountPath: "/var/run/secrets/kubernetes.io/serviceaccount",
								},
								{
									Name:      "bao-agent-config",
									MountPath: "/bao/agent/",
								},
							},
						},
						{
							Name: "consul-template",
							Args: []string{"-config", "/bao/ct-config/config.hcl", "-once"},
							Resources: corev1.ResourceRequirements{
								Limits: corev1.ResourceList{
									corev1.ResourceCPU:    resource.MustParse("50m"),
									corev1.ResourceMemory: resource.MustParse("128Mi"),
								},
							},
							Env: []corev1.EnvVar{
								{
									Name:  "BAO_ADDR",
									Value: "test",
								},
								{
									Name:  "BAO_SKIP_VERIFY",
									Value: "false",
								},
							},
							SecurityContext: baseSecurityContext,
							VolumeMounts: []corev1.VolumeMount{
								{
									Name:      "secret-init",
									MountPath: "/bao/",
								},
								{
									Name:      "ct-secrets",
									MountPath: "/bao/secrets",
								},
								{
									Name:      "secret-init",
									MountPath: "/home/consul-template",
								},
								{
									Name:      "ct-configmap",
									ReadOnly:  true,
									MountPath: "/bao/ct-config/config.hcl",
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
								{Name: "ct-secrets", MountPath: "/bao/secrets"},
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
									MountPath: "/bao/secrets",
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
							Name: "bao-agent-config",
							VolumeSource: corev1.VolumeSource{
								ConfigMap: &corev1.ConfigMapVolumeSource{
									LocalObjectReference: corev1.LocalObjectReference{
										Name: "-bao-agent-config",
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
			name: "Will mutate pod with bao-ct-inject-in-initcontainers and without ct-once annotations",
			fields: fields{
				k8sClient: fake.NewSimpleClientset(),
				registry: &MockRegistry{
					Image: v1.Config{},
				},
			},
			args: args{
				pod: &corev1.Pod{
					Spec: corev1.PodSpec{
						InitContainers: []corev1.Container{
							{
								Name:    "MyInitContainer",
								Image:   "myInitimage",
								Command: []string{"/bin/bash"},
								Args:    nil,
								VolumeMounts: []corev1.VolumeMount{
									{
										MountPath: "/var/run/secrets/bao",
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
										MountPath: "/var/run/secrets/bao",
									},
								},
							},
						},
					},
				},
				webhookConfig: appCommon.Config{
					RunAsNonRoot: true,
					RunAsUser:    int64(1000),
					RunAsGroup:   int64(1000),
				},
				secretInitConfig: appCommon.SecretInitConfig{
					CPURequest:    resource.MustParse("50m"),
					MemoryRequest: resource.MustParse("64Mi"),
					CPULimit:      resource.MustParse("250m"),
					MemoryLimit:   resource.MustParse("64Mi"),
				},
				baoConfig: Config{
					CtConfigMap:                   "config-map-test",
					CtInjectInInitcontainers:      true,
					ConfigfilePath:                "/bao/secrets",
					Addr:                          "test",
					SkipVerify:                    false,
					CtCPU:                         resource.MustParse("50m"),
					CtMemory:                      resource.MustParse("128Mi"),
					AgentImage:                    "openbao/bao:latest",
					AgentImagePullPolicy:          "IfNotPresent",
					ServiceAccountTokenVolumeName: "/var/run/secrets/bao",
				},
			},
			wantedPod: &corev1.Pod{
				Spec: corev1.PodSpec{
					InitContainers: []corev1.Container{
						{
							Name:            "bao-agent",
							Image:           "openbao/bao:latest",
							Command:         []string{"bao", "agent", "-config=/bao/agent/config.hcl", "-exit-after-auth"},
							ImagePullPolicy: "IfNotPresent",
							Env: []corev1.EnvVar{
								{
									Name:  "BAO_ADDR",
									Value: "test",
								},
								{
									Name:  "BAO_SKIP_VERIFY",
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
									MountPath: "/bao/",
								},
								{
									MountPath: "/var/run/secrets/bao",
								},
								{
									Name:      "bao-agent-config",
									MountPath: "/bao/agent/",
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
									MountPath: "/var/run/secrets/bao",
								},
							},
						},
					},
					Containers: []corev1.Container{
						{
							Name: "consul-template",
							Args: []string{"-config", "/bao/ct-config/config.hcl"},
							Resources: corev1.ResourceRequirements{
								Limits: corev1.ResourceList{
									corev1.ResourceCPU:    resource.MustParse("50m"),
									corev1.ResourceMemory: resource.MustParse("128Mi"),
								},
							},
							Env: []corev1.EnvVar{
								{
									Name:  "BAO_ADDR",
									Value: "test",
								},
								{
									Name:  "BAO_SKIP_VERIFY",
									Value: "false",
								},
							},
							SecurityContext: baseSecurityContext,
							VolumeMounts: []corev1.VolumeMount{
								{
									Name:      "secret-init",
									MountPath: "/bao/",
								},
								{
									Name:      "ct-secrets",
									MountPath: "/bao/secrets",
								},
								{
									Name:      "secret-init",
									MountPath: "/home/consul-template",
								},
								{
									Name:      "ct-configmap",
									ReadOnly:  true,
									MountPath: "/bao/ct-config/config.hcl",
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
									MountPath: "/var/run/secrets/bao",
								},
								{
									Name:      "ct-secrets",
									MountPath: "/bao/secrets",
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
							Name: "bao-agent-config",
							VolumeSource: corev1.VolumeSource{
								ConfigMap: &corev1.ConfigMapVolumeSource{
									LocalObjectReference: corev1.LocalObjectReference{
										Name: "-bao-agent-config",
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
			mutator := mutator{client: nil, config: &ttp.args.baoConfig, logger: slog.Default()}

			err := mutator.MutatePod(context.Background(), ttp.args.pod, ttp.args.webhookConfig, ttp.args.secretInitConfig, ttp.fields.k8sClient, ttp.fields.registry, false)
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
