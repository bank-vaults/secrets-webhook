// Copyright © 2021 Banzai Cloud
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package vault

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strconv"
	"strings"

	"emperror.dev/errors"
	"github.com/bank-vaults/internal/injector"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kubeVer "k8s.io/apimachinery/pkg/version"
	"k8s.io/client-go/kubernetes"

	"github.com/bank-vaults/secrets-webhook/pkg/common"
	"github.com/bank-vaults/secrets-webhook/pkg/registry"
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

func podMutator(ctx context.Context, pod *corev1.Pod, appConfig common.AppConfig, secretInitConfig common.SecretInitConfig, config Config, k8sClient kubernetes.Interface, registry registry.ImageRegistry, logger *slog.Logger, dryRun bool) error {
	logger.Debug("Successfully connected to the API")

	if isPodAlreadyMutated(pod) {
		slog.Info(fmt.Sprintf("Pod %s is already mutated, skipping mutation.", pod.Name))
		return nil
	}

	initContainersMutated, err := mutateContainers(ctx, pod.Spec.InitContainers, &pod.Spec, appConfig, secretInitConfig, config, k8sClient, registry)
	if err != nil {
		return err
	}

	if initContainersMutated {
		slog.Debug("Successfully mutated pod init containers")
	} else {
		slog.Debug("No pod init containers were mutated")
	}

	containersMutated, err := mutateContainers(ctx, pod.Spec.Containers, &pod.Spec, appConfig, secretInitConfig, config, k8sClient, registry)
	if err != nil {
		return err
	}

	if containersMutated {
		slog.Debug("Successfully mutated pod containers")
	} else {
		slog.Debug("No pod containers were mutated")
	}

	containerEnvVars := []corev1.EnvVar{
		{
			Name:  "VAULT_ADDR",
			Value: config.Addr,
		},
		{
			Name:  "VAULT_SKIP_VERIFY",
			Value: strconv.FormatBool(config.SkipVerify),
		},
	}

	if config.Token != "" {
		containerEnvVars = append(containerEnvVars, corev1.EnvVar{
			Name:  "VAULT_TOKEN",
			Value: config.Token,
		})
	}

	containerVolMounts := []corev1.VolumeMount{
		{
			Name:      SecretInitVolumeName,
			MountPath: "/vault/",
		},
	}
	if config.TLSSecret != "" {
		mountPath := "/vault/tls/"
		volumeName := "vault-tls"
		if hasTLSVolume(pod.Spec.Volumes) {
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

	if config.CtConfigMap != "" {
		slog.Debug("Consul Template config found")

		addSecretsVolToContainers(config, pod.Spec.Containers)

		if config.CtShareProcessDefault == "empty" {
			slog.Debug("Test our Kubernetes API Version and make the final decision on enabling ShareProcessNamespace")
			apiVersion, _ := k8sClient.Discovery().ServerVersion()
			versionCompared := kubeVer.CompareKubeAwareVersionStrings("v1.12.0", apiVersion.String())
			slog.Debug(fmt.Sprintf("Kubernetes API version detected: %s", apiVersion.String()))

			if versionCompared >= 0 {
				config.CtShareProcess = true
			} else {
				config.CtShareProcess = false
			}
		}

		if config.CtShareProcess {
			slog.Debug("Detected shared process namespace")
			shareProcessNamespace := true
			pod.Spec.ShareProcessNamespace = &shareProcessNamespace
		}
		if !config.CtOnce {
			pod.Spec.Containers = append(getContainers(pod.Spec.SecurityContext, appConfig, config, containerEnvVars, containerVolMounts), pod.Spec.Containers...)
		} else {
			if config.CtInjectInInitcontainers {
				addSecretsVolToContainers(config, pod.Spec.InitContainers)
			}
			pod.Spec.InitContainers = append(getContainers(pod.Spec.SecurityContext, appConfig, config, containerEnvVars, containerVolMounts), pod.Spec.InitContainers...)
		}

		slog.Debug("Successfully appended pod containers to spec")
	}

	if initContainersMutated || containersMutated || config.CtConfigMap != "" || config.AgentConfigMap != "" {
		var agentConfigMapName string

		if config.UseAgent || config.CtConfigMap != "" {
			if config.AgentConfigMap != "" {
				agentConfigMapName = config.AgentConfigMap
			} else {
				configMap := getConfigMapForVaultAgent(pod, config)
				agentConfigMapName = configMap.Name
				if !dryRun {
					_, err := k8sClient.CoreV1().ConfigMaps(config.ObjectNamespace).Create(context.Background(), configMap, metav1.CreateOptions{})
					if err != nil {
						if apierrors.IsAlreadyExists(err) {
							_, err = k8sClient.CoreV1().ConfigMaps(config.ObjectNamespace).Update(context.Background(), configMap, metav1.UpdateOptions{})
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

		pod.Spec.InitContainers = append(getInitContainers(pod.Spec.Containers, pod.Spec.SecurityContext, appConfig, secretInitConfig, config, initContainersMutated, containersMutated, containerEnvVars, containerVolMounts), pod.Spec.InitContainers...)
		slog.Debug("Successfully appended pod init containers to spec")

		pod.Spec.Volumes = append(pod.Spec.Volumes, getVolumes(pod.Spec.Volumes, agentConfigMapName, config)...)
		slog.Debug("Successfully appended pod spec volumes")
	}

	if config.AgentConfigMap != "" && !config.UseAgent {
		slog.Debug("Vault Agent config found")

		addAgentSecretsVolToContainers(config, pod.Spec.Containers)

		if config.AgentShareProcessDefault == "empty" {
			slog.Debug("Test our Kubernetes API Version and make the final decision on enabling ShareProcessNamespace")
			apiVersion, _ := k8sClient.Discovery().ServerVersion()
			versionCompared := kubeVer.CompareKubeAwareVersionStrings("v1.12.0", apiVersion.String())
			slog.Debug(fmt.Sprintf("Kubernetes API version detected: %s", apiVersion.String()))

			if versionCompared >= 0 {
				config.AgentShareProcess = true
			} else {
				config.AgentShareProcess = false
			}
		}

		if config.AgentShareProcess {
			slog.Debug("Detected shared process namespace")
			shareProcessNamespace := true
			pod.Spec.ShareProcessNamespace = &shareProcessNamespace
		}
		pod.Spec.Containers = append(getAgentContainers(pod.Spec.Containers, pod.Spec.SecurityContext, appConfig, config, containerEnvVars, containerVolMounts), pod.Spec.Containers...)

		slog.Debug("Successfully appended pod containers to spec")
	}

	return nil
}

func isPodAlreadyMutated(pod *corev1.Pod) bool {
	for _, volume := range pod.Spec.Volumes {
		if volume.Name == SecretInitVolumeName {
			return true
		}
	}
	return false
}

func mutateContainers(ctx context.Context, containers []corev1.Container, podSpec *corev1.PodSpec, appConfig common.AppConfig, secretInitConfig common.SecretInitConfig, config Config, k8sClient kubernetes.Interface, registry registry.ImageRegistry) (bool, error) {
	mutated := false

	for i, container := range containers {
		var envVars []corev1.EnvVar
		if len(container.EnvFrom) > 0 {
			envFrom, err := lookForEnvFrom(k8sClient, container.EnvFrom, config.ObjectNamespace)
			if err != nil {
				return false, err
			}
			envVars = append(envVars, envFrom...)
		}

		for _, env := range container.Env {
			if common.HasVaultPrefix(env.Value) || injector.HasInlineVaultDelimiters(env.Value) {
				envVars = append(envVars, env)
			}
			if env.ValueFrom != nil {
				valueFrom, err := lookForValueFrom(k8sClient, env, config.ObjectNamespace)
				if err != nil {
					return false, err
				}
				if valueFrom == nil {
					continue
				}
				envVars = append(envVars, *valueFrom)
			}
		}

		if len(envVars) == 0 && config.FromPath == "" {
			continue
		}

		mutated = true

		args := container.Command

		// the container has no explicitly specified command
		if len(args) == 0 {
			imageConfig, err := registry.GetImageConfig(ctx, k8sClient, config.ObjectNamespace, appConfig.RegistrySkipVerify, &container, podSpec) //nolint:gosec
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

		container.Command = []string{"/vault/secret-init"}
		container.Args = args

		// mutate probes if needed
		if appConfig.MutateProbes {
			// mutate LivenessProbe
			if container.LivenessProbe != nil && container.LivenessProbe.Exec != nil {
				lProbeCmd := container.LivenessProbe.Exec.Command
				container.LivenessProbe.Exec.Command = []string{"/vault/secret-init"}
				container.LivenessProbe.Exec.Command = append(container.LivenessProbe.Exec.Command, lProbeCmd...)
			}
			// mutate LivenessProbe
			if container.ReadinessProbe != nil && container.ReadinessProbe.Exec != nil {
				rProbeCmd := container.ReadinessProbe.Exec.Command
				container.ReadinessProbe.Exec.Command = []string{"/vault/secret-init"}
				container.ReadinessProbe.Exec.Command = append(container.ReadinessProbe.Exec.Command, rProbeCmd...)
			}
		}

		container.VolumeMounts = append(container.VolumeMounts, []corev1.VolumeMount{
			{
				Name:      SecretInitVolumeName,
				MountPath: "/vault/",
			},
		}...)

		container.Env = append(container.Env, []corev1.EnvVar{
			{
				Name:  "VAULT_ADDR",
				Value: config.Addr,
			},
			{
				Name:  "VAULT_SKIP_VERIFY",
				Value: strconv.FormatBool(config.SkipVerify),
			},
			{
				Name:  "VAULT_AUTH_METHOD",
				Value: config.AuthMethod,
			},
			{
				Name:  "VAULT_PATH",
				Value: config.Path,
			},
			{
				Name:  "VAULT_ROLE",
				Value: config.Role,
			},
			{
				Name:  "VAULT_IGNORE_MISSING_SECRETS",
				Value: config.IgnoreMissingSecrets,
			},
			{
				Name:  "VAULT_PASSTHROUGH",
				Value: config.Passthrough,
			},
			{
				Name:  "SECRET_INIT_JSON_LOG",
				Value: secretInitConfig.JSONLog,
			},
			{
				Name:  "VAULT_CLIENT_TIMEOUT",
				Value: config.ClientTimeout.String(),
			},
		}...)

		if config.Token != "" {
			container.Env = append(container.Env, corev1.EnvVar{
				Name:  "VAULT_TOKEN",
				Value: config.Token,
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

		if len(config.TransitKeyID) > 0 {
			container.Env = append(container.Env, []corev1.EnvVar{
				{
					Name:  "VAULT_TRANSIT_KEY_ID",
					Value: config.TransitKeyID,
				},
			}...)
		}

		if len(config.TransitPath) > 0 {
			container.Env = append(container.Env, []corev1.EnvVar{
				{
					Name:  "VAULT_TRANSIT_PATH",
					Value: config.TransitPath,
				},
			}...)
		}

		if config.TransitBatchSize > 0 {
			container.Env = append(container.Env, []corev1.EnvVar{
				{
					Name:  "VAULT_TRANSIT_BATCH_SIZE",
					Value: strconv.Itoa(config.TransitBatchSize),
				},
			}...)
		}

		if len(config.VaultNamespace) > 0 {
			container.Env = append(container.Env, []corev1.EnvVar{
				{
					Name:  "VAULT_NAMESPACE",
					Value: config.VaultNamespace,
				},
			}...)
		}

		if config.TLSSecret != "" {
			mountPath := "/vault/tls/"
			volumeName := "vault-tls"
			if hasTLSVolume(podSpec.Volumes) {
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

		if config.UseAgent || config.TokenAuthMount != "" {
			container.Env = append(container.Env, corev1.EnvVar{
				Name:  "VAULT_TOKEN_FILE",
				Value: "/vault/.vault-token",
			})
		}

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

		if config.FromPath != "" {
			container.Env = append(container.Env, corev1.EnvVar{
				Name:  "VAULT_FROM_PATH",
				Value: config.FromPath,
			})
		}

		if secretInitConfig.LogServer != "" {
			container.Env = append(container.Env, corev1.EnvVar{
				Name:  "SECRET_INIT_LOG_SERVER",
				Value: secretInitConfig.LogServer,
			})
		}

		containers[i] = container
	}

	return mutated, nil
}

func lookForEnvFrom(k8sClient kubernetes.Interface, envFrom []corev1.EnvFromSource, ns string) ([]corev1.EnvVar, error) {
	var envVars []corev1.EnvVar

	for _, ef := range envFrom {
		if ef.ConfigMapRef != nil {
			data, err := common.GetDataFromConfigmap(k8sClient, ef.ConfigMapRef.Name, ns)
			if err != nil {
				if apierrors.IsNotFound(err) || (ef.ConfigMapRef.Optional != nil && *ef.ConfigMapRef.Optional) {
					continue
				}

				return envVars, err
			}
			for key, value := range data {
				if common.HasVaultPrefix(value) || injector.HasInlineVaultDelimiters(value) {
					envFromCM := corev1.EnvVar{
						Name:  key,
						Value: value,
					}
					envVars = append(envVars, envFromCM)
				}
			}
		}
		if ef.SecretRef != nil {
			data, err := common.GetDataFromSecret(k8sClient, ef.SecretRef.Name, ns)
			if err != nil {
				if apierrors.IsNotFound(err) || (ef.SecretRef.Optional != nil && *ef.SecretRef.Optional) {
					continue
				}

				return envVars, err
			}
			for name, v := range data {
				value := string(v)
				if common.HasVaultPrefix(value) || injector.HasInlineVaultDelimiters(value) {
					envFromSec := corev1.EnvVar{
						Name:  name,
						Value: value,
					}
					envVars = append(envVars, envFromSec)
				}
			}
		}
	}
	return envVars, nil
}

func lookForValueFrom(k8sClient kubernetes.Interface, env corev1.EnvVar, ns string) (*corev1.EnvVar, error) {
	if env.ValueFrom.ConfigMapKeyRef != nil {
		data, err := common.GetDataFromConfigmap(k8sClient, env.ValueFrom.ConfigMapKeyRef.Name, ns)
		if err != nil {
			if apierrors.IsNotFound(err) {
				return nil, nil
			}
			return nil, err
		}
		value := data[env.ValueFrom.ConfigMapKeyRef.Key]
		if common.HasVaultPrefix(value) || injector.HasInlineVaultDelimiters(value) {
			fromCM := corev1.EnvVar{
				Name:  env.Name,
				Value: value,
			}
			return &fromCM, nil
		}
	}
	if env.ValueFrom.SecretKeyRef != nil {
		data, err := common.GetDataFromSecret(k8sClient, env.ValueFrom.SecretKeyRef.Name, ns)
		if err != nil {
			if apierrors.IsNotFound(err) {
				return nil, nil
			}
			return nil, err
		}
		value := string(data[env.ValueFrom.SecretKeyRef.Key])
		if common.HasVaultPrefix(value) || injector.HasInlineVaultDelimiters(value) {
			fromSecret := corev1.EnvVar{
				Name:  env.Name,
				Value: value,
			}
			return &fromSecret, nil
		}
	}
	return nil, nil
}

func addSecretsVolToContainers(config Config, containers []corev1.Container) {
	for i, container := range containers {
		slog.Debug(fmt.Sprintf("Add secrets VolumeMount to container %s", container.Name))

		container.VolumeMounts = append(container.VolumeMounts, []corev1.VolumeMount{
			{
				Name:      "ct-secrets",
				MountPath: config.ConfigfilePath,
			},
		}...)

		containers[i] = container
	}
}

func addAgentSecretsVolToContainers(config Config, containers []corev1.Container) {
	for i, container := range containers {
		slog.Debug(fmt.Sprintf("Add secrets VolumeMount to container %s", container.Name))

		container.VolumeMounts = append(container.VolumeMounts, []corev1.VolumeMount{
			{
				Name:      "agent-secrets",
				MountPath: config.ConfigfilePath,
			},
		}...)

		containers[i] = container
	}
}

func getVolumes(existingVolumes []corev1.Volume, agentConfigMapName string, config Config) []corev1.Volume {
	slog.Debug("Add generic volumes to podspec")

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

	if config.UseAgent || config.CtConfigMap != "" {
		slog.Debug("Add vault agent volumes to podspec")
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

	if config.TLSSecret != "" {
		slog.Debug("Add vault TLS volume to podspec")

		volumeName := "vault-tls"
		if hasTLSVolume(existingVolumes) {
			volumeName = "secret-init-tls"
		}

		volumes = append(volumes, corev1.Volume{
			Name: volumeName,
			VolumeSource: corev1.VolumeSource{
				Projected: &corev1.ProjectedVolumeSource{
					Sources: []corev1.VolumeProjection{{
						Secret: &corev1.SecretProjection{
							LocalObjectReference: corev1.LocalObjectReference{
								Name: config.TLSSecret,
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
	if config.CtConfigMap != "" {
		slog.Debug("Add consul template volumes to podspec")

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
							Name: config.CtConfigMap,
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

	if config.AgentConfigMap != "" {
		slog.Debug("Add vault-agent volumes to podspec")

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
							Name: config.AgentConfigMap,
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
func hasTLSVolume(volumes []corev1.Volume) bool {
	for _, volume := range volumes {
		if volume.Name == "vault-tls" {
			return true
		}
	}
	return false
}

func getServiceAccountMount(containers []corev1.Container, config Config) (serviceAccountMount corev1.VolumeMount) {
mountSearch:
	for _, container := range containers {
		for _, mount := range container.VolumeMounts {
			if mount.MountPath == config.ServiceAccountTokenVolumeName {
				serviceAccountMount = mount

				break mountSearch
			}
		}
	}

	return serviceAccountMount
}

func getInitContainers(originalContainers []corev1.Container, podSecurityContext *corev1.PodSecurityContext, appConfig common.AppConfig, secretInitConfig common.SecretInitConfig, config Config, initContainersMutated bool, containersMutated bool, containerEnvVars []corev1.EnvVar, containerVolMounts []corev1.VolumeMount) []corev1.Container {
	containers := []corev1.Container{}

	if config.TokenAuthMount != "" {
		// vault.security.banzaicloud.io/token-auth-mount: "token:vault-token"
		split := strings.Split(config.TokenAuthMount, ":")
		mountName := split[0]
		tokenName := split[1]
		fileLoc := "/token/" + tokenName
		cmd := fmt.Sprintf("cp %s /vault/.vault-token", fileLoc)

		containers = append(containers, corev1.Container{
			Name:            "copy-vault-token",
			Image:           config.AgentImage,
			ImagePullPolicy: config.AgentImagePullPolicy,
			Command:         []string{"sh", "-c", cmd},
			SecurityContext: getBaseSecurityContext(podSecurityContext, appConfig),
			Resources: corev1.ResourceRequirements{
				Limits: corev1.ResourceList{
					corev1.ResourceCPU:    resource.MustParse("50m"),
					corev1.ResourceMemory: resource.MustParse("64Mi"),
				},
			},
			VolumeMounts: []corev1.VolumeMount{
				{
					Name:      SecretInitVolumeName,
					MountPath: "/vault/",
				},
				{
					Name:      mountName,
					MountPath: "/token",
				},
			},
		})
	} else if config.Token == "" && (config.UseAgent || config.CtConfigMap != "") {
		serviceAccountMount := getServiceAccountMount(originalContainers, config)

		containerVolMounts = append(containerVolMounts, serviceAccountMount, corev1.VolumeMount{
			Name:      "vault-agent-config",
			MountPath: "/vault/agent/",
		})

		securityContext := getBaseSecurityContext(podSecurityContext, appConfig)
		securityContext.Capabilities.Add = []corev1.Capability{
			"CHOWN",
			"SETFCAP",
			"SETGID",
			"SETPCAP",
			"SETUID",
		}

		containers = append(containers, corev1.Container{
			Name:            "vault-agent",
			Image:           config.AgentImage,
			ImagePullPolicy: config.AgentImagePullPolicy,
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
			Command:         []string{"sh", "-c", "cp /usr/local/bin/secret-init /vault/"},
			VolumeMounts: []corev1.VolumeMount{
				{
					Name:      SecretInitVolumeName,
					MountPath: "/vault/",
				},
			},

			SecurityContext: getBaseSecurityContext(podSecurityContext, appConfig),
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

func getContainers(podSecurityContext *corev1.PodSecurityContext, appConfig common.AppConfig, config Config, containerEnvVars []corev1.EnvVar, containerVolMounts []corev1.VolumeMount) []corev1.Container {
	containers := []corev1.Container{}
	securityContext := getBaseSecurityContext(podSecurityContext, appConfig)

	if config.CtShareProcess {
		securityContext.Capabilities.Add = append(securityContext.Capabilities.Add, "SYS_PTRACE")
	}

	containerVolMounts = append(containerVolMounts, corev1.VolumeMount{
		Name:      "ct-secrets",
		MountPath: config.ConfigfilePath,
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
	if config.CtOnce {
		ctCommandString = []string{"-config", "/vault/ct-config/config.hcl", "-once"}
	} else {
		ctCommandString = []string{"-config", "/vault/ct-config/config.hcl"}
	}

	containers = append(containers, corev1.Container{
		Name:            "consul-template",
		Image:           config.CtImage,
		Args:            ctCommandString,
		ImagePullPolicy: config.CtImagePullPolicy,
		SecurityContext: securityContext,
		Env:             containerEnvVars,
		VolumeMounts:    containerVolMounts,
		Resources: corev1.ResourceRequirements{
			Limits: corev1.ResourceList{
				corev1.ResourceCPU:    config.CtCPU,
				corev1.ResourceMemory: config.CtMemory,
			},
		},
	})

	return containers
}

func getAgentContainers(originalContainers []corev1.Container, podSecurityContext *corev1.PodSecurityContext, appConfig common.AppConfig, config Config, containerEnvVars []corev1.EnvVar, containerVolMounts []corev1.VolumeMount) []corev1.Container {
	containers := []corev1.Container{}

	securityContext := getBaseSecurityContext(podSecurityContext, appConfig)
	securityContext.Capabilities.Add = []corev1.Capability{
		"CHOWN",
		"SETFCAP",
		"SETGID",
		"SETPCAP",
		"SETUID",
		"IPC_LOCK",
	}

	if config.AgentShareProcess {
		securityContext.Capabilities.Add = append(securityContext.Capabilities.Add, "SYS_PTRACE")
	}

	serviceAccountMount := getServiceAccountMount(originalContainers, config)

	containerVolMounts = append(containerVolMounts, serviceAccountMount, corev1.VolumeMount{
		Name:      "agent-secrets",
		MountPath: config.ConfigfilePath,
	}, corev1.VolumeMount{
		Name:      "agent-configmap",
		MountPath: "/vault/config/config.hcl",
		ReadOnly:  true,
		SubPath:   "config.hcl",
	},
	)

	var agentCommandString []string
	if config.AgentOnce {
		agentCommandString = []string{"agent", "-config", "/vault/config/config.hcl", "-exit-after-auth"}
	} else {
		agentCommandString = []string{"agent", "-config", "/vault/config/config.hcl"}
	}

	if config.AgentEnvVariables != "" {
		var envVars []corev1.EnvVar
		err := json.Unmarshal([]byte(config.AgentEnvVariables), &envVars)
		if err != nil {
			envVars = []corev1.EnvVar{}
		}
		containerEnvVars = append(containerEnvVars, envVars...)
	}

	containers = append(containers, corev1.Container{
		Name:            "vault-agent",
		Image:           config.AgentImage,
		Args:            agentCommandString,
		ImagePullPolicy: config.AgentImagePullPolicy,
		SecurityContext: securityContext,
		Env:             containerEnvVars,
		VolumeMounts:    containerVolMounts,
		Resources: corev1.ResourceRequirements{
			Limits: corev1.ResourceList{
				corev1.ResourceCPU:    config.AgentCPULimit,
				corev1.ResourceMemory: config.AgentMemoryLimit,
			},
			Requests: corev1.ResourceList{
				corev1.ResourceCPU:    config.AgentCPURequest,
				corev1.ResourceMemory: config.AgentMemoryRequest,
			},
		},
	})

	return containers
}

func getBaseSecurityContext(podSecurityContext *corev1.PodSecurityContext, appConfig common.AppConfig) *corev1.SecurityContext {
	context := &corev1.SecurityContext{
		AllowPrivilegeEscalation: &appConfig.PspAllowPrivilegeEscalation,
		ReadOnlyRootFilesystem:   &appConfig.ReadOnlyRootFilesystem,
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
	if appConfig.RunAsNonRoot {
		context.RunAsNonRoot = &appConfig.RunAsNonRoot
	}

	if appConfig.RunAsUser > 0 {
		context.RunAsUser = &appConfig.RunAsUser
	}

	if appConfig.RunAsGroup > 0 {
		context.RunAsGroup = &appConfig.RunAsGroup
	}

	return context
}

func getConfigMapForVaultAgent(pod *corev1.Pod, config Config) *corev1.ConfigMap {
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
			"config.hcl": fmt.Sprintf(vaultAgentConfig, config.VaultNamespace, config.Path, config.Role),
		},
	}
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
