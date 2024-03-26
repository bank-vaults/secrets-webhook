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
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"emperror.dev/errors"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kubeVer "k8s.io/apimachinery/pkg/version"

	"github.com/bank-vaults/secrets-webhook/pkg/common"
	"github.com/bank-vaults/secrets-webhook/pkg/provider/bao"
	"github.com/bank-vaults/secrets-webhook/pkg/provider/vault"
)

const (
	vaultAgentConfig = `
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
	SecretInitVolumeName = "secret-init"
)

func (mw *MutatingWebhook) MutatePod(ctx context.Context, pod *corev1.Pod, webhookConfig common.Config, secretInitConfig common.SecretInitConfig, dryRun bool, configs []interface{}) error {
	mw.logger.Debug("Successfully connected to the API")

	for _, config := range configs {
		switch providerConfig := config.(type) {
		case vault.Config:
			currentlyUsedProvider = vault.ProviderName

			err := mw.mutatePodForVault(ctx, pod, webhookConfig, secretInitConfig, providerConfig, dryRun)
			if err != nil {
				return errors.Wrap(err, "failed to mutate secret")
			}

		default:
			return errors.Errorf("unknown provider config type: %T", config)
		}
	}

	return nil
}

func getBaseSecurityContext(podSecurityContext *corev1.PodSecurityContext, webhookConfig common.Config) *corev1.SecurityContext {
	context := &corev1.SecurityContext{
		AllowPrivilegeEscalation: &webhookConfig.PspAllowPrivilegeEscalation,
		ReadOnlyRootFilesystem:   &webhookConfig.ReadOnlyRootFilesystem,
		Capabilities: &corev1.Capabilities{
			Add: []corev1.Capability{},
			Drop: []corev1.Capability{
				"ALL",
			},
		},
	}

	if podSecurityContext != nil && podSecurityContext.RunAsUser != nil {
		context.RunAsUser = podSecurityContext.RunAsUser
	}

	// Although it could explicitly be set to false,
	// the behavior of false and unset are the same
	if webhookConfig.RunAsNonRoot {
		context.RunAsNonRoot = &webhookConfig.RunAsNonRoot
	}

	if webhookConfig.RunAsUser > 0 {
		context.RunAsUser = &webhookConfig.RunAsUser
	}

	if webhookConfig.RunAsGroup > 0 {
		context.RunAsGroup = &webhookConfig.RunAsGroup
	}

	return context
}

// isLogLevelSet checks if the SECRET_INIT_LOG_LEVEL environment variable
// has already been set in the container, so it doesn't get overridden.
func isLogLevelSet(envVars []corev1.EnvVar) bool {
	for _, envVar := range envVars {
		if envVar.Name == "SECRET_INIT_LOG_LEVEL" {
			return true
		}
	}
	return false
}

func isPodAlreadyMutated(pod *corev1.Pod) bool {
	for _, volume := range pod.Spec.Volumes {
		if volume.Name == SecretInitVolumeName {
			return true
		}
	}
	return false
}

func (mw *MutatingWebhook) mutateContainers(ctx context.Context, containers []corev1.Container, podSpec *corev1.PodSpec, webhookConfig common.Config, secretInitConfig common.SecretInitConfig, vaultConfig vault.Config) (bool, error) {
	mutated := false

	for i, container := range containers {
		var envVars []corev1.EnvVar
		if len(container.EnvFrom) > 0 {
			envFrom, err := mw.lookForEnvFrom(container.EnvFrom, vaultConfig.ObjectNamespace)
			if err != nil {
				return false, err
			}
			envVars = append(envVars, envFrom...)
		}

		for _, env := range container.Env {
			if hasProviderPrefix(currentlyUsedProvider, env.Value, true) {
				envVars = append(envVars, env)
			}
			if env.ValueFrom != nil {
				valueFrom, err := mw.lookForValueFrom(env, vaultConfig.ObjectNamespace)
				if err != nil {
					return false, err
				}
				if valueFrom == nil {
					continue
				}
				envVars = append(envVars, *valueFrom)
			}
		}

		if len(envVars) == 0 && vaultConfig.FromPath == "" {
			continue
		}

		mutated = true

		args := container.Command

		// the container has no explicitly specified command
		if len(args) == 0 {
			imageConfig, err := mw.registry.GetImageConfig(ctx, mw.k8sClient, vaultConfig.ObjectNamespace, webhookConfig.RegistrySkipVerify, &container, podSpec) //nolint:gosec
			if err != nil {
				return false, err
			}

			args = append(args, imageConfig.Entrypoint...)

			// If no Args are defined we can use the Docker CMD from the image
			// https://kubernetes.io/docs/tasks/inject-data-application/define-command-argument-container/#notes
			if len(container.Args) == 0 {
				args = append(args, imageConfig.Cmd...)
			}
		}

		args = append(args, container.Args...)

		container.Command = []string{"/bank-vaults/secret-init"}
		container.Args = args

		// mutate probes if needed
		if webhookConfig.MutateProbes {
			// mutate LivenessProbe
			if container.LivenessProbe != nil && container.LivenessProbe.Exec != nil {
				lProbeCmd := container.LivenessProbe.Exec.Command
				container.LivenessProbe.Exec.Command = []string{"/bank-vaults/secret-init"}
				container.LivenessProbe.Exec.Command = append(container.LivenessProbe.Exec.Command, lProbeCmd...)
			}
			// mutate LivenessProbe
			if container.ReadinessProbe != nil && container.ReadinessProbe.Exec != nil {
				rProbeCmd := container.ReadinessProbe.Exec.Command
				container.ReadinessProbe.Exec.Command = []string{"/bank-vaults/secret-init"}
				container.ReadinessProbe.Exec.Command = append(container.ReadinessProbe.Exec.Command, rProbeCmd...)
			}
		}

		container.VolumeMounts = append(container.VolumeMounts, []corev1.VolumeMount{
			{
				Name:      SecretInitVolumeName,
				MountPath: "/bank-vaults/",
			},
		}...)

		if secretInitConfig.Daemon {
			container.Env = append(container.Env, corev1.EnvVar{
				Name:  "SECRET_INIT_DAEMON",
				Value: "true",
			})
		}

		if secretInitConfig.Delay > 0 {
			container.Env = append(container.Env, corev1.EnvVar{
				Name:  "SECRET_INIT_DELAY",
				Value: secretInitConfig.Delay.String(),
			})
		}

		if secretInitConfig.LogServer != "" {
			container.Env = append(container.Env, corev1.EnvVar{
				Name:  "SECRET_INIT_LOG_SERVER",
				Value: secretInitConfig.LogServer,
			})
		}

		if !isLogLevelSet(container.Env) && secretInitConfig.LogLevel != "" {
			container.Env = append(container.Env, []corev1.EnvVar{
				{
					Name:  "SECRET_INIT_LOG_LEVEL",
					Value: secretInitConfig.LogLevel,
				},
			}...)
		}

		switch currentlyUsedProvider {
		case vault.ProviderName:
			container.Env = append(container.Env, []corev1.EnvVar{
				{
					Name:  "VAULT_ADDR",
					Value: vaultConfig.Addr,
				},
				{
					Name:  "VAULT_SKIP_VERIFY",
					Value: strconv.FormatBool(vaultConfig.SkipVerify),
				},
				{
					Name:  "VAULT_AUTH_METHOD",
					Value: vaultConfig.AuthMethod,
				},
				{
					Name:  "VAULT_PATH",
					Value: vaultConfig.Path,
				},
				{
					Name:  "VAULT_ROLE",
					Value: vaultConfig.Role,
				},
				{
					Name:  "VAULT_IGNORE_MISSING_SECRETS",
					Value: vaultConfig.IgnoreMissingSecrets,
				},
				{
					Name:  "VAULT_PASSTHROUGH",
					Value: vaultConfig.Passthrough,
				},
				{
					Name:  "SECRET_INIT_JSON_LOG",
					Value: secretInitConfig.JSONLog,
				},
				{
					Name:  "VAULT_CLIENT_TIMEOUT",
					Value: vaultConfig.ClientTimeout.String(),
				},
			}...)

			if vaultConfig.Token != "" {
				container.Env = append(container.Env, corev1.EnvVar{
					Name:  "VAULT_TOKEN",
					Value: vaultConfig.Token,
				})
			}

			if len(vaultConfig.TransitKeyID) > 0 {
				container.Env = append(container.Env, []corev1.EnvVar{
					{
						Name:  "VAULT_TRANSIT_KEY_ID",
						Value: vaultConfig.TransitKeyID,
					},
				}...)
			}

			if len(vaultConfig.TransitPath) > 0 {
				container.Env = append(container.Env, []corev1.EnvVar{
					{
						Name:  "VAULT_TRANSIT_PATH",
						Value: vaultConfig.TransitPath,
					},
				}...)
			}

			if vaultConfig.TransitBatchSize > 0 {
				container.Env = append(container.Env, []corev1.EnvVar{
					{
						Name:  "VAULT_TRANSIT_BATCH_SIZE",
						Value: strconv.Itoa(vaultConfig.TransitBatchSize),
					},
				}...)
			}

			if len(vaultConfig.VaultNamespace) > 0 {
				container.Env = append(container.Env, []corev1.EnvVar{
					{
						Name:  "VAULT_NAMESPACE",
						Value: vaultConfig.VaultNamespace,
					},
				}...)
			}

			if vaultConfig.TLSSecret != "" {
				mountPath := "/vault/tls/"
				volumeName := "vault-tls"
				if hasTLSVolume_Vault(podSpec.Volumes) {
					mountPath = "/secret-init/tls/"
					volumeName = "secret-init-tls"
				}

				container.Env = append(container.Env, corev1.EnvVar{
					Name:  "VAULT_CACERT",
					Value: mountPath + "ca.crt",
				})
				container.VolumeMounts = append(container.VolumeMounts, corev1.VolumeMount{
					Name:      volumeName,
					MountPath: mountPath,
				})
			}

			if vaultConfig.UseAgent || vaultConfig.TokenAuthMount != "" {
				container.Env = append(container.Env, corev1.EnvVar{
					Name:  "VAULT_TOKEN_FILE",
					Value: "/vault/.vault-token",
				})
			}

			if vaultConfig.FromPath != "" {
				container.Env = append(container.Env, corev1.EnvVar{
					Name:  "VAULT_FROM_PATH",
					Value: vaultConfig.FromPath,
				})
			}

		case bao.ProviderName:

		default:
			return false, errors.Errorf("unknown provider: %s", currentlyUsedProvider)
		}

		containers[i] = container
	}

	return mutated, nil
}

func (mw *MutatingWebhook) addSecretsVolToContainers_Vault(vaultConfig vault.Config, containers []corev1.Container) {
	for i, container := range containers {
		mw.logger.Debug(fmt.Sprintf("Add secrets VolumeMount to container %s", container.Name))

		container.VolumeMounts = append(container.VolumeMounts, []corev1.VolumeMount{
			{
				Name:      "ct-secrets",
				MountPath: vaultConfig.ConfigfilePath,
			},
		}...)

		containers[i] = container
	}
}

func (mw *MutatingWebhook) addAgentSecretsVolToContainers_Vault(vaultConfig vault.Config, containers []corev1.Container) {
	for i, container := range containers {
		mw.logger.Debug(fmt.Sprintf("Add secrets VolumeMount to container %s", container.Name))

		container.VolumeMounts = append(container.VolumeMounts, []corev1.VolumeMount{
			{
				Name:      "agent-secrets",
				MountPath: vaultConfig.ConfigfilePath,
			},
		}...)

		containers[i] = container
	}
}

func (mw *MutatingWebhook) getVolumes_Vault(existingVolumes []corev1.Volume, agentConfigMapName string, vaultConfig vault.Config) []corev1.Volume {
	mw.logger.Debug("Add generic volumes to podspec")

	volumes := []corev1.Volume{
		{
			Name: SecretInitVolumeName,
			VolumeSource: corev1.VolumeSource{
				EmptyDir: &corev1.EmptyDirVolumeSource{
					Medium: corev1.StorageMediumMemory,
				},
			},
		},
	}

	if vaultConfig.UseAgent || vaultConfig.CtConfigMap != "" {
		mw.logger.Debug("Add vault agent volumes to podspec")
		volumes = append(volumes, corev1.Volume{
			Name: "vault-agent-config",
			VolumeSource: corev1.VolumeSource{
				ConfigMap: &corev1.ConfigMapVolumeSource{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: agentConfigMapName,
					},
				},
			},
		})
	}

	if vaultConfig.TLSSecret != "" {
		mw.logger.Debug("Add vault TLS volume to podspec")

		volumeName := "vault-tls"
		if hasTLSVolume_Vault(existingVolumes) {
			volumeName = "secret-init-tls"
		}

		volumes = append(volumes, corev1.Volume{
			Name: volumeName,
			VolumeSource: corev1.VolumeSource{
				Projected: &corev1.ProjectedVolumeSource{
					Sources: []corev1.VolumeProjection{{
						Secret: &corev1.SecretProjection{
							LocalObjectReference: corev1.LocalObjectReference{
								Name: vaultConfig.TLSSecret,
							},
							Items: []corev1.KeyToPath{{
								Key:  "ca.crt",
								Path: "ca.crt",
							}},
						},
					}},
				},
			},
		})
	}
	if vaultConfig.CtConfigMap != "" {
		mw.logger.Debug("Add consul template volumes to podspec")

		defaultMode := int32(420)
		volumes = append(volumes,
			corev1.Volume{
				Name: "ct-secrets",
				VolumeSource: corev1.VolumeSource{
					EmptyDir: &corev1.EmptyDirVolumeSource{
						Medium: corev1.StorageMediumMemory,
					},
				},
			},
			corev1.Volume{
				Name: "ct-configmap",
				VolumeSource: corev1.VolumeSource{
					ConfigMap: &corev1.ConfigMapVolumeSource{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: vaultConfig.CtConfigMap,
						},
						DefaultMode: &defaultMode,
						Items: []corev1.KeyToPath{
							{
								Key:  "config.hcl",
								Path: "config.hcl",
							},
						},
					},
				},
			})
	}

	if vaultConfig.AgentConfigMap != "" {
		mw.logger.Debug("Add vault-agent volumes to podspec")

		defaultMode := int32(420)
		volumes = append(volumes,
			corev1.Volume{
				Name: "agent-secrets",
				VolumeSource: corev1.VolumeSource{
					EmptyDir: &corev1.EmptyDirVolumeSource{
						Medium: corev1.StorageMediumMemory,
					},
				},
			},
			corev1.Volume{
				Name: "agent-configmap",
				VolumeSource: corev1.VolumeSource{
					ConfigMap: &corev1.ConfigMapVolumeSource{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: vaultConfig.AgentConfigMap,
						},
						DefaultMode: &defaultMode,
						Items: []corev1.KeyToPath{
							{
								Key:  "config.hcl",
								Path: "config.hcl",
							},
						},
					},
				},
			})
	}

	return volumes
}

// If the original Pod contained a Volume "vault-tls", for example Vault instances provisioned by the Operator
// we need to handle that edge case and choose another name for the vault-tls volume for accessing Vault with TLS.
func hasTLSVolume_Vault(volumes []corev1.Volume) bool {
	for _, volume := range volumes {
		if volume.Name == "vault-tls" {
			return true
		}
	}
	return false
}

func getServiceAccountMount_Vault(containers []corev1.Container, vaultConfig vault.Config) (serviceAccountMount corev1.VolumeMount) {
mountSearch:
	for _, container := range containers {
		for _, mount := range container.VolumeMounts {
			if mount.MountPath == vaultConfig.ServiceAccountTokenVolumeName {
				serviceAccountMount = mount

				break mountSearch
			}
		}
	}
	return serviceAccountMount
}

func getInitContainers_Vault(originalContainers []corev1.Container, podSecurityContext *corev1.PodSecurityContext, webhookConfig common.Config, secretInitConfig common.SecretInitConfig, vaultConfig vault.Config, initContainersMutated bool, containersMutated bool, containerEnvVars []corev1.EnvVar, containerVolMounts []corev1.VolumeMount) []corev1.Container {
	containers := []corev1.Container{}

	if vaultConfig.TokenAuthMount != "" {
		// vault.security.banzaicloud.io/token-auth-mount: "token:vault-token"
		split := strings.Split(vaultConfig.TokenAuthMount, ":")
		mountName := split[0]
		tokenName := split[1]
		fileLoc := "/token/" + tokenName
		cmd := fmt.Sprintf("cp %s /vault/.vault-token", fileLoc)

		containers = append(containers, corev1.Container{
			Name:            "copy-vault-token",
			Image:           vaultConfig.AgentImage,
			ImagePullPolicy: vaultConfig.AgentImagePullPolicy,
			Command:         []string{"sh", "-c", cmd},
			SecurityContext: getBaseSecurityContext(podSecurityContext, webhookConfig),
			Resources: corev1.ResourceRequirements{
				Limits: corev1.ResourceList{
					corev1.ResourceCPU:    resource.MustParse("50m"),
					corev1.ResourceMemory: resource.MustParse("64Mi"),
				},
			},
			VolumeMounts: []corev1.VolumeMount{
				{
					Name:      SecretInitVolumeName,
					MountPath: "/bank-vaults/",
				},
				{
					Name:      mountName,
					MountPath: "/token",
				},
			},
		})
	} else if vaultConfig.Token == "" && (vaultConfig.UseAgent || vaultConfig.CtConfigMap != "") {
		serviceAccountMount := getServiceAccountMount_Vault(originalContainers, vaultConfig)

		containerVolMounts = append(containerVolMounts, serviceAccountMount, corev1.VolumeMount{
			Name:      "vault-agent-config",
			MountPath: "/vault/agent/",
		})

		securityContext := getBaseSecurityContext(podSecurityContext, webhookConfig)
		securityContext.Capabilities.Add = []corev1.Capability{
			"CHOWN",
			"SETFCAP",
			"SETGID",
			"SETPCAP",
			"SETUID",
		}

		containers = append(containers, corev1.Container{
			Name:            "vault-agent",
			Image:           vaultConfig.AgentImage,
			ImagePullPolicy: vaultConfig.AgentImagePullPolicy,
			SecurityContext: securityContext,
			Command:         []string{"vault", "agent", "-config=/vault/agent/config.hcl", "-exit-after-auth"},
			Env:             containerEnvVars,
			VolumeMounts:    containerVolMounts,
			Resources: corev1.ResourceRequirements{
				Limits: corev1.ResourceList{
					corev1.ResourceCPU:    secretInitConfig.CPULimit,
					corev1.ResourceMemory: secretInitConfig.MemoryLimit,
				},
				Requests: corev1.ResourceList{
					corev1.ResourceCPU:    secretInitConfig.CPURequest,
					corev1.ResourceMemory: secretInitConfig.MemoryRequest,
				},
			},
		})
	}

	if initContainersMutated || containersMutated {
		containers = append(containers, corev1.Container{
			Name:            "copy-secret-init",
			Image:           secretInitConfig.Image,
			ImagePullPolicy: secretInitConfig.ImagePullPolicy,
			Command:         []string{"sh", "-c", "cp /usr/local/bin/secret-init /bank-vaults/"},
			VolumeMounts: []corev1.VolumeMount{
				{
					Name:      SecretInitVolumeName,
					MountPath: "/bank-vaults/",
				},
			},

			SecurityContext: getBaseSecurityContext(podSecurityContext, webhookConfig),
			Resources: corev1.ResourceRequirements{
				Limits: corev1.ResourceList{
					corev1.ResourceCPU:    secretInitConfig.CPULimit,
					corev1.ResourceMemory: secretInitConfig.MemoryLimit,
				},
				Requests: corev1.ResourceList{
					corev1.ResourceCPU:    secretInitConfig.CPURequest,
					corev1.ResourceMemory: secretInitConfig.MemoryRequest,
				},
			},
		})
	}

	return containers
}

func getContainers_Vault(podSecurityContext *corev1.PodSecurityContext, webhookConfig common.Config, vaultConfig vault.Config, containerEnvVars []corev1.EnvVar, containerVolMounts []corev1.VolumeMount) []corev1.Container {
	containers := []corev1.Container{}
	securityContext := getBaseSecurityContext(podSecurityContext, webhookConfig)

	if vaultConfig.CtShareProcess {
		securityContext.Capabilities.Add = append(securityContext.Capabilities.Add, "SYS_PTRACE")
	}

	containerVolMounts = append(containerVolMounts, corev1.VolumeMount{
		Name:      "ct-secrets",
		MountPath: vaultConfig.ConfigfilePath,
	}, corev1.VolumeMount{
		Name:      SecretInitVolumeName,
		MountPath: "/home/consul-template",
	}, corev1.VolumeMount{
		Name:      "ct-configmap",
		MountPath: "/vault/ct-config/config.hcl",
		ReadOnly:  true,
		SubPath:   "config.hcl",
	},
	)

	var ctCommandString []string
	if vaultConfig.CtOnce {
		ctCommandString = []string{"-config", "/vault/ct-config/config.hcl", "-once"}
	} else {
		ctCommandString = []string{"-config", "/vault/ct-config/config.hcl"}
	}

	containers = append(containers, corev1.Container{
		Name:            "consul-template",
		Image:           vaultConfig.CtImage,
		Args:            ctCommandString,
		ImagePullPolicy: vaultConfig.CtImagePullPolicy,
		SecurityContext: securityContext,
		Env:             containerEnvVars,
		VolumeMounts:    containerVolMounts,
		Resources: corev1.ResourceRequirements{
			Limits: corev1.ResourceList{
				corev1.ResourceCPU:    vaultConfig.CtCPU,
				corev1.ResourceMemory: vaultConfig.CtMemory,
			},
		},
	})

	return containers
}

func getAgentContainers_Vault(originalContainers []corev1.Container, podSecurityContext *corev1.PodSecurityContext, webhookConfig common.Config, vaultConfig vault.Config, containerEnvVars []corev1.EnvVar, containerVolMounts []corev1.VolumeMount) []corev1.Container {
	containers := []corev1.Container{}

	securityContext := getBaseSecurityContext(podSecurityContext, webhookConfig)
	securityContext.Capabilities.Add = []corev1.Capability{
		"CHOWN",
		"SETFCAP",
		"SETGID",
		"SETPCAP",
		"SETUID",
		"IPC_LOCK",
	}

	if vaultConfig.AgentShareProcess {
		securityContext.Capabilities.Add = append(securityContext.Capabilities.Add, "SYS_PTRACE")
	}

	serviceAccountMount := getServiceAccountMount_Vault(originalContainers, vaultConfig)

	containerVolMounts = append(containerVolMounts, serviceAccountMount, corev1.VolumeMount{
		Name:      "agent-secrets",
		MountPath: vaultConfig.ConfigfilePath,
	}, corev1.VolumeMount{
		Name:      "agent-configmap",
		MountPath: "/vault/config/config.hcl",
		ReadOnly:  true,
		SubPath:   "config.hcl",
	},
	)

	var agentCommandString []string
	if vaultConfig.AgentOnce {
		agentCommandString = []string{"agent", "-config", "/vault/config/config.hcl", "-exit-after-auth"}
	} else {
		agentCommandString = []string{"agent", "-config", "/vault/config/config.hcl"}
	}

	if vaultConfig.AgentEnvVariables != "" {
		var envVars []corev1.EnvVar
		err := json.Unmarshal([]byte(vaultConfig.AgentEnvVariables), &envVars)
		if err != nil {
			envVars = []corev1.EnvVar{}
		}
		containerEnvVars = append(containerEnvVars, envVars...)
	}

	containers = append(containers, corev1.Container{
		Name:            "vault-agent",
		Image:           vaultConfig.AgentImage,
		Args:            agentCommandString,
		ImagePullPolicy: vaultConfig.AgentImagePullPolicy,
		SecurityContext: securityContext,
		Env:             containerEnvVars,
		VolumeMounts:    containerVolMounts,
		Resources: corev1.ResourceRequirements{
			Limits: corev1.ResourceList{
				corev1.ResourceCPU:    vaultConfig.AgentCPULimit,
				corev1.ResourceMemory: vaultConfig.AgentMemoryLimit,
			},
			Requests: corev1.ResourceList{
				corev1.ResourceCPU:    vaultConfig.AgentCPURequest,
				corev1.ResourceMemory: vaultConfig.AgentMemoryRequest,
			},
		},
	})

	return containers
}

func getConfigMapForVaultAgent_Vault(pod *corev1.Pod, vaultConfig vault.Config) *corev1.ConfigMap {
	ownerReferences := pod.GetOwnerReferences()
	name := pod.GetName()
	// If we have no name we are probably part of some controller,
	// try to get the name of the owner controller.
	if name == "" {
		if len(ownerReferences) > 0 {
			if strings.Contains(ownerReferences[0].Name, "-") {
				generateNameSlice := strings.Split(ownerReferences[0].Name, "-")
				name = strings.Join(generateNameSlice[:len(generateNameSlice)-1], "-")
			} else {
				name = ownerReferences[0].Name
			}
		}
	}
	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:            name + "-vault-agent-config",
			OwnerReferences: ownerReferences,
		},
		Data: map[string]string{
			"config.hcl": fmt.Sprintf(vaultAgentConfig, vaultConfig.VaultNamespace, vaultConfig.Path, vaultConfig.Role),
		},
	}
}

// ======== VAULT ========

func (mw *MutatingWebhook) mutatePodForVault(ctx context.Context, pod *corev1.Pod, webhookConfig common.Config, secretInitConfig common.SecretInitConfig, vaultConfig vault.Config, dryRun bool) error {
	if isPodAlreadyMutated(pod) {
		mw.logger.Info(fmt.Sprintf("Pod %s is already mutated, skipping mutation.", pod.Name))
		return nil
	}

	initContainersMutated, err := mw.mutateContainers(ctx, pod.Spec.InitContainers, &pod.Spec, webhookConfig, secretInitConfig, vaultConfig)
	if err != nil {
		return err
	}

	if initContainersMutated {
		mw.logger.Debug("Successfully mutated pod init containers")
	} else {
		mw.logger.Debug("No pod init containers were mutated")
	}

	containersMutated, err := mw.mutateContainers(ctx, pod.Spec.Containers, &pod.Spec, webhookConfig, secretInitConfig, vaultConfig)
	if err != nil {
		return err
	}

	if containersMutated {
		mw.logger.Debug("Successfully mutated pod containers")
	} else {
		mw.logger.Debug("No pod containers were mutated")
	}

	containerEnvVars := []corev1.EnvVar{
		{
			Name:  "VAULT_ADDR",
			Value: vaultConfig.Addr,
		},
		{
			Name:  "VAULT_SKIP_VERIFY",
			Value: strconv.FormatBool(vaultConfig.SkipVerify),
		},
	}

	if vaultConfig.Token != "" {
		containerEnvVars = append(containerEnvVars, corev1.EnvVar{
			Name:  "VAULT_TOKEN",
			Value: vaultConfig.Token,
		})
	}

	containerVolMounts := []corev1.VolumeMount{
		{
			Name:      SecretInitVolumeName,
			MountPath: "/bank-vaults/",
		},
	}
	if vaultConfig.TLSSecret != "" {
		mountPath := "/vault/tls/"
		volumeName := "vault-tls"
		if hasTLSVolume_Vault(pod.Spec.Volumes) {
			mountPath = "/secret-init/tls/"
			volumeName = "secret-init-tls"
		}

		containerEnvVars = append(containerEnvVars, corev1.EnvVar{
			Name:  "VAULT_CACERT",
			Value: mountPath + "ca.crt",
		})
		containerVolMounts = append(containerVolMounts, corev1.VolumeMount{
			Name:      volumeName,
			MountPath: mountPath,
		})
	}

	if vaultConfig.CtConfigMap != "" {
		mw.logger.Debug("Consul Template config found")

		mw.addSecretsVolToContainers_Vault(vaultConfig, pod.Spec.Containers)

		if vaultConfig.CtShareProcessDefault == "empty" {
			mw.logger.Debug("Test our Kubernetes API Version and make the final decision on enabling ShareProcessNamespace")
			apiVersion, _ := mw.k8sClient.Discovery().ServerVersion()
			versionCompared := kubeVer.CompareKubeAwareVersionStrings("v1.12.0", apiVersion.String())
			mw.logger.Debug(fmt.Sprintf("Kubernetes API version detected: %s", apiVersion.String()))

			if versionCompared >= 0 {
				vaultConfig.CtShareProcess = true
			} else {
				vaultConfig.CtShareProcess = false
			}
		}

		if vaultConfig.CtShareProcess {
			mw.logger.Debug("Detected shared process namespace")
			shareProcessNamespace := true
			pod.Spec.ShareProcessNamespace = &shareProcessNamespace
		}
		if !vaultConfig.CtOnce {
			pod.Spec.Containers = append(getContainers_Vault(pod.Spec.SecurityContext, webhookConfig, vaultConfig, containerEnvVars, containerVolMounts), pod.Spec.Containers...)
		} else {
			if vaultConfig.CtInjectInInitcontainers {
				mw.addSecretsVolToContainers_Vault(vaultConfig, pod.Spec.InitContainers)
			}
			pod.Spec.InitContainers = append(getContainers_Vault(pod.Spec.SecurityContext, webhookConfig, vaultConfig, containerEnvVars, containerVolMounts), pod.Spec.InitContainers...)
		}

		mw.logger.Debug("Successfully appended pod containers to spec")
	}

	if initContainersMutated || containersMutated || vaultConfig.CtConfigMap != "" || vaultConfig.AgentConfigMap != "" {
		var agentConfigMapName string

		if vaultConfig.UseAgent || vaultConfig.CtConfigMap != "" {
			if vaultConfig.AgentConfigMap != "" {
				agentConfigMapName = vaultConfig.AgentConfigMap
			} else {
				configMap := getConfigMapForVaultAgent_Vault(pod, vaultConfig)
				agentConfigMapName = configMap.Name
				if !dryRun {
					_, err := mw.k8sClient.CoreV1().ConfigMaps(vaultConfig.ObjectNamespace).Create(context.Background(), configMap, metav1.CreateOptions{})
					if err != nil {
						if apierrors.IsAlreadyExists(err) {
							_, err = mw.k8sClient.CoreV1().ConfigMaps(vaultConfig.ObjectNamespace).Update(context.Background(), configMap, metav1.UpdateOptions{})
							if err != nil {
								return errors.WrapIf(err, "failed to update ConfigMap for config")
							}
						} else {
							return errors.WrapIf(err, "failed to create ConfigMap for config")
						}
					}
				}
			}
		}

		pod.Spec.InitContainers = append(getInitContainers_Vault(pod.Spec.Containers, pod.Spec.SecurityContext, webhookConfig, secretInitConfig, vaultConfig, initContainersMutated, containersMutated, containerEnvVars, containerVolMounts), pod.Spec.InitContainers...)
		mw.logger.Debug("Successfully appended pod init containers to spec")

		pod.Spec.Volumes = append(pod.Spec.Volumes, mw.getVolumes_Vault(pod.Spec.Volumes, agentConfigMapName, vaultConfig)...)
		mw.logger.Debug("Successfully appended pod spec volumes")
	}

	if vaultConfig.AgentConfigMap != "" && !vaultConfig.UseAgent {
		mw.logger.Debug("Vault Agent config found")

		mw.addAgentSecretsVolToContainers_Vault(vaultConfig, pod.Spec.Containers)

		if vaultConfig.AgentShareProcessDefault == "empty" {
			mw.logger.Debug("Test our Kubernetes API Version and make the final decision on enabling ShareProcessNamespace")
			apiVersion, _ := mw.k8sClient.Discovery().ServerVersion()
			versionCompared := kubeVer.CompareKubeAwareVersionStrings("v1.12.0", apiVersion.String())
			mw.logger.Debug(fmt.Sprintf("Kubernetes API version detected: %s", apiVersion.String()))

			if versionCompared >= 0 {
				vaultConfig.AgentShareProcess = true
			} else {
				vaultConfig.AgentShareProcess = false
			}
		}

		if vaultConfig.AgentShareProcess {
			mw.logger.Debug("Detected shared process namespace")
			shareProcessNamespace := true
			pod.Spec.ShareProcessNamespace = &shareProcessNamespace
		}
		pod.Spec.Containers = append(getAgentContainers_Vault(pod.Spec.Containers, pod.Spec.SecurityContext, webhookConfig, vaultConfig, containerEnvVars, containerVolMounts), pod.Spec.Containers...)

		mw.logger.Debug("Successfully appended pod containers to spec")
	}

	return nil
}
