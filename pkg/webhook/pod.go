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

const SecretInitVolumeName = "secret-init"

func (mw *MutatingWebhook) MutatePod(ctx context.Context, pod *corev1.Pod, webhookConfig common.Config, secretInitConfig common.SecretInitConfig, config interface{}, dryRun bool) error {
	if isPodAlreadyMutated(pod) {
		mw.logger.Info(fmt.Sprintf("Pod %s is already mutated, skipping mutation.", pod.Name))
		return nil
	}

	mw.logger.Debug("Successfully connected to the API")

	switch providerConfig := config.(type) {
	case vault.Config:
		err := mw.mutatePodForVault(ctx, pod, webhookConfig, secretInitConfig, providerConfig, dryRun)
		if err != nil {
			return errors.Wrap(err, "failed to mutate secret")
		}

	case bao.Config:
		err := mw.mutatePodForBao(ctx, pod, webhookConfig, secretInitConfig, providerConfig, dryRun)
		if err != nil {
			return errors.Wrap(err, "failed to mutate secret")
		}

	default:
		return errors.Errorf("unknown provider config type: %T", config)
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

func isSecretInitAlreadyMounted(podSpec *corev1.PodSpec) bool {
	if podSpec == nil {
		return false
	}

	for _, volume := range podSpec.Volumes {
		if volume.Name == SecretInitVolumeName {
			return true
		}
	}

	return false
}

func isSecretInitContainerExists(containers []corev1.Container) bool {
	for _, container := range containers {
		if container.Name == "copy-secret-init" {
			return true
		}
	}
	return false
}

func areProbesAlreadyMutated(container *corev1.Container) bool {
	if container.LivenessProbe != nil && container.LivenessProbe.Exec != nil {
		if len(container.LivenessProbe.Exec.Command) > 0 && container.LivenessProbe.Exec.Command[0] == "/bank-vaults/secret-init" {
			return true
		}
	}

	if container.ReadinessProbe != nil && container.ReadinessProbe.Exec != nil {
		if len(container.ReadinessProbe.Exec.Command) > 0 && container.ReadinessProbe.Exec.Command[0] == "/bank-vaults/secret-init" {
			return true
		}
	}

	if container.StartupProbe != nil && container.StartupProbe.Exec != nil {
		if len(container.StartupProbe.Exec.Command) > 0 && container.StartupProbe.Exec.Command[0] == "/bank-vaults/secret-init" {
			return true
		}
	}

	return false
}

func (mw *MutatingWebhook) mutateContainers(ctx context.Context, containers []corev1.Container, podSpec *corev1.PodSpec, webhookConfig common.Config, secretInitConfig common.SecretInitConfig, config interface{}, objectNamespace string, fromPath string) (bool, error) {
	mutated := false

	for i, container := range containers {
		var envVars []corev1.EnvVar
		if len(container.EnvFrom) > 0 {
			envFrom, err := mw.lookForEnvFrom(container.EnvFrom, objectNamespace)
			if err != nil {
				return false, err
			}
			envVars = append(envVars, envFrom...)
		}

		for _, env := range container.Env {
			if hasProviderPrefix(env.Value, true) {
				envVars = append(envVars, env)
			}

			if env.ValueFrom != nil {
				valueFrom, err := mw.lookForValueFrom(env, objectNamespace)
				if err != nil {
					return false, err
				}

				if valueFrom == nil {
					continue
				}
				envVars = append(envVars, *valueFrom)
			}
		}

		if len(envVars) == 0 && fromPath == "" {
			continue
		}

		mutated = true

		args := container.Command

		// the container has no explicitly specified command
		if len(args) == 0 {
			imageConfig, err := mw.registry.GetImageConfig(ctx, mw.k8sClient, objectNamespace, webhookConfig.RegistrySkipVerify, &container, podSpec) //nolint:gosec
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

		// mutate probes if needed
		if !areProbesAlreadyMutated(&container) {
			if webhookConfig.MutateProbes {
				// mutate LivenessProbe
				if container.LivenessProbe != nil && container.LivenessProbe.Exec != nil {
					lProbeCmd := container.LivenessProbe.Exec.Command
					container.LivenessProbe.Exec.Command = []string{"/bank-vaults/secret-init"}
					container.LivenessProbe.Exec.Command = append(container.LivenessProbe.Exec.Command, lProbeCmd...)
				}

				// mutate ReadinessProbe
				if container.ReadinessProbe != nil && container.ReadinessProbe.Exec != nil {
					rProbeCmd := container.ReadinessProbe.Exec.Command
					container.ReadinessProbe.Exec.Command = []string{"/bank-vaults/secret-init"}
					container.ReadinessProbe.Exec.Command = append(container.ReadinessProbe.Exec.Command, rProbeCmd...)
				}

				// mutate StartupProbe
				if container.StartupProbe != nil && container.StartupProbe.Exec != nil {
					sProbeCmd := container.StartupProbe.Exec.Command
					container.StartupProbe.Exec.Command = []string{"/bank-vaults/secret-init"}
					container.StartupProbe.Exec.Command = append(container.StartupProbe.Exec.Command, sProbeCmd...)
				}

			}

		}

		if !isSecretInitAlreadyMounted(podSpec) {
			container.Command = []string{"/bank-vaults/secret-init"}
			container.Args = args

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
		}

		mw.setEnvVarsForProvider(&container, podSpec, secretInitConfig, config)

		containers[i] = container
	}

	return mutated, nil
}

func (mw *MutatingWebhook) setEnvVarsForProvider(container *corev1.Container, podSpec *corev1.PodSpec, secretInitConfig common.SecretInitConfig, config interface{}) {
	switch config := config.(type) {
	case vault.Config:
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
			if hasTLSVolume(podSpec.Volumes, volumeName) {
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

		if config.FromPath != "" {
			container.Env = append(container.Env, corev1.EnvVar{
				Name:  "VAULT_FROM_PATH",
				Value: config.FromPath,
			})
		}

	case bao.Config:
		container.Env = append(container.Env, []corev1.EnvVar{
			{
				Name:  "BAO_ADDR",
				Value: config.Addr,
			},
			{
				Name:  "BAO_SKIP_VERIFY",
				Value: strconv.FormatBool(config.SkipVerify),
			},
			{
				Name:  "BAO_AUTH_METHOD",
				Value: config.AuthMethod,
			},
			{
				Name:  "BAO_PATH",
				Value: config.Path,
			},
			{
				Name:  "BAO_ROLE",
				Value: config.Role,
			},
			{
				Name:  "BAO_IGNORE_MISSING_SECRETS",
				Value: config.IgnoreMissingSecrets,
			},
			{
				Name:  "BAO_PASSTHROUGH",
				Value: config.Passthrough,
			},
			{
				Name:  "SECRET_INIT_JSON_LOG",
				Value: secretInitConfig.JSONLog,
			},
			{
				Name:  "BAO_CLIENT_TIMEOUT",
				Value: config.ClientTimeout.String(),
			},
		}...)

		if config.Token != "" {
			container.Env = append(container.Env, corev1.EnvVar{
				Name:  "BAO_TOKEN",
				Value: config.Token,
			})
		}

		if len(config.TransitKeyID) > 0 {
			container.Env = append(container.Env, []corev1.EnvVar{
				{
					Name:  "BAO_TRANSIT_KEY_ID",
					Value: config.TransitKeyID,
				},
			}...)
		}

		if len(config.TransitPath) > 0 {
			container.Env = append(container.Env, []corev1.EnvVar{
				{
					Name:  "BAO_TRANSIT_PATH",
					Value: config.TransitPath,
				},
			}...)
		}

		if config.TransitBatchSize > 0 {
			container.Env = append(container.Env, []corev1.EnvVar{
				{
					Name:  "BAO_TRANSIT_BATCH_SIZE",
					Value: strconv.Itoa(config.TransitBatchSize),
				},
			}...)
		}

		if len(config.BaoNamespace) > 0 {
			container.Env = append(container.Env, []corev1.EnvVar{
				{
					Name:  "BAO_NAMESPACE",
					Value: config.BaoNamespace,
				},
			}...)
		}

		if config.TLSSecret != "" {
			mountPath := "/bao/tls/"
			volumeName := "bao-tls"
			if hasTLSVolume(podSpec.Volumes, volumeName) {
				mountPath = "/secret-init/tls/"
				volumeName = "secret-init-tls"
			}

			container.Env = append(container.Env, corev1.EnvVar{
				Name:  "BAO_CACERT",
				Value: mountPath + "ca.crt",
			})
			container.VolumeMounts = append(container.VolumeMounts, corev1.VolumeMount{
				Name:      volumeName,
				MountPath: mountPath,
			})
		}

		if config.UseAgent || config.TokenAuthMount != "" {
			container.Env = append(container.Env, corev1.EnvVar{
				Name:  "BAO_TOKEN_FILE",
				Value: "/bao/.bao-token",
			})
		}

		if config.FromPath != "" {
			container.Env = append(container.Env, corev1.EnvVar{
				Name:  "BAO_FROM_PATH",
				Value: config.FromPath,
			})
		}

	default:
		mw.logger.Error("Unknown provider config type")
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

// If the original Pod contained a Volume "{providerName}-tls", for example Vault instances provisioned by the Operator
// we need to handle that edge case and choose another name for the vault-tls volume for accessing Vault with TLS.
func hasTLSVolume(volumes []corev1.Volume, tls string) bool {
	for _, volume := range volumes {
		if volume.Name == tls {
			return true
		}
	}

	return false
}

func (mw *MutatingWebhook) addSecretsVolToContainers(containers []corev1.Container, configFilePath string) {
	for i, container := range containers {
		mw.logger.Debug(fmt.Sprintf("Add secrets VolumeMount to container %s", container.Name))

		container.VolumeMounts = append(container.VolumeMounts, []corev1.VolumeMount{
			{
				Name:      "ct-secrets-" + currentlyUsedProvider,
				MountPath: configFilePath,
			},
		}...)

		containers[i] = container
	}
}

func createCopySecretInitContainer(secretInitConfig common.SecretInitConfig, podSecurityContext *corev1.PodSecurityContext, webhookConfig common.Config) corev1.Container {
	return corev1.Container{
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
	}
}

func (mw *MutatingWebhook) addAgentSecretsVolToContainers(containers []corev1.Container, configFilePath string) {
	for i, container := range containers {
		mw.logger.Debug(fmt.Sprintf("Add secrets VolumeMount to container %s", container.Name))

		container.VolumeMounts = append(container.VolumeMounts, []corev1.VolumeMount{
			{
				Name:      "agent-secrets-" + currentlyUsedProvider,
				MountPath: configFilePath,
			},
		}...)

		containers[i] = container
	}
}

func getServiceAccountMount(containers []corev1.Container, serviceAccountTokenVolumeName string) (serviceAccountMount corev1.VolumeMount) {
mountSearch:
	for _, container := range containers {
		for _, mount := range container.VolumeMounts {
			if mount.MountPath == serviceAccountTokenVolumeName {
				serviceAccountMount = mount

				break mountSearch
			}
		}
	}

	return serviceAccountMount
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

// ======== VAULT ========

func (mw *MutatingWebhook) mutatePodForVault(ctx context.Context, pod *corev1.Pod, webhookConfig common.Config, secretInitConfig common.SecretInitConfig, vaultConfig vault.Config, dryRun bool) error {
	initContainersMutated, err := mw.mutateContainers(ctx, pod.Spec.InitContainers, &pod.Spec, webhookConfig, secretInitConfig, vaultConfig, vaultConfig.ObjectNamespace, vaultConfig.FromPath)
	if err != nil {
		return err
	}

	if initContainersMutated {
		mw.logger.Debug("Successfully mutated pod init containers")
	} else {
		mw.logger.Debug("No pod init containers were mutated")
	}

	containersMutated, err := mw.mutateContainers(ctx, pod.Spec.Containers, &pod.Spec, webhookConfig, secretInitConfig, vaultConfig, vaultConfig.ObjectNamespace, vaultConfig.FromPath)
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

	containerVolMounts := []corev1.VolumeMount{}
	if !isSecretInitAlreadyMounted(&pod.Spec) {
		containerVolMounts = []corev1.VolumeMount{
			{
				Name:      SecretInitVolumeName,
				MountPath: "/bank-vaults/",
			},
		}
	}

	if vaultConfig.TLSSecret != "" {
		mountPath := "/vault/tls/"
		volumeName := "vault-tls"
		if hasTLSVolume(pod.Spec.Volumes, volumeName) {
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

		mw.addSecretsVolToContainers(pod.Spec.Containers, vaultConfig.ConfigfilePath)

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
			pod.Spec.Containers = append(getContainersForVault(pod.Spec.SecurityContext, webhookConfig, vaultConfig, containerEnvVars, containerVolMounts), pod.Spec.Containers...)
		} else {
			if vaultConfig.CtInjectInInitcontainers {
				mw.addSecretsVolToContainers(pod.Spec.InitContainers, vaultConfig.ConfigfilePath)
			}
			pod.Spec.InitContainers = append(getContainersForVault(pod.Spec.SecurityContext, webhookConfig, vaultConfig, containerEnvVars, containerVolMounts), pod.Spec.InitContainers...)
		}

		mw.logger.Debug("Successfully appended pod containers to spec")
	}

	if initContainersMutated || containersMutated || vaultConfig.CtConfigMap != "" || vaultConfig.AgentConfigMap != "" {
		var agentConfigMapName string

		if vaultConfig.UseAgent || vaultConfig.CtConfigMap != "" {
			if vaultConfig.AgentConfigMap != "" {
				agentConfigMapName = vaultConfig.AgentConfigMap
			} else {
				configMap := getConfigMapForVaultAgent(pod, vaultConfig)
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

		pod.Spec.InitContainers = append(getInitContainersForVault(pod.Spec.Containers, pod.Spec.SecurityContext, webhookConfig, secretInitConfig, vaultConfig, initContainersMutated, containersMutated, containerEnvVars, containerVolMounts), pod.Spec.InitContainers...)
		mw.logger.Debug("Successfully appended pod init containers to spec")

		pod.Spec.Volumes = append(pod.Spec.Volumes, mw.getVolumesForVault(pod.Spec.Volumes, agentConfigMapName, vaultConfig)...)
		mw.logger.Debug("Successfully appended pod spec volumes")
	}

	if vaultConfig.AgentConfigMap != "" && !vaultConfig.UseAgent {
		mw.logger.Debug("Vault Agent config found")

		mw.addAgentSecretsVolToContainers(pod.Spec.Containers, vaultConfig.ConfigfilePath)

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
		pod.Spec.Containers = append(getAgentContainersForVault(pod.Spec.Containers, pod.Spec.SecurityContext, webhookConfig, vaultConfig, containerEnvVars, containerVolMounts), pod.Spec.Containers...)

		mw.logger.Debug("Successfully appended pod containers to spec")
	}

	return nil
}

func getContainersForVault(podSecurityContext *corev1.PodSecurityContext, webhookConfig common.Config, vaultConfig vault.Config, containerEnvVars []corev1.EnvVar, containerVolMounts []corev1.VolumeMount) []corev1.Container {
	containers := []corev1.Container{}
	securityContext := getBaseSecurityContext(podSecurityContext, webhookConfig)

	if vaultConfig.CtShareProcess {
		securityContext.Capabilities.Add = append(securityContext.Capabilities.Add, "SYS_PTRACE")
	}

	containerVolMounts = append(containerVolMounts, corev1.VolumeMount{
		Name:      "ct-secrets-vault",
		MountPath: vaultConfig.ConfigfilePath,
	}, corev1.VolumeMount{
		Name:      SecretInitVolumeName,
		MountPath: "/home/consul-template-vault",
	}, corev1.VolumeMount{
		Name:      "ct-configmap-vault",
		MountPath: "/vault/ct-config/config.hcl",
		ReadOnly:  true,
		SubPath:   "config.hcl",
	})

	var ctCommandString []string
	if vaultConfig.CtOnce {
		ctCommandString = []string{"-config", "/vault/ct-config/config.hcl", "-once"}
	} else {
		ctCommandString = []string{"-config", "/vault/ct-config/config.hcl"}
	}

	containers = append(containers, corev1.Container{
		Name:            "consul-template-vault",
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

func getConfigMapForVaultAgent(pod *corev1.Pod, vaultConfig vault.Config) *corev1.ConfigMap {
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
			"config.hcl": fmt.Sprintf(vault.AgentConfig, vaultConfig.VaultNamespace, vaultConfig.Path, vaultConfig.Role),
		},
	}
}

func getInitContainersForVault(originalContainers []corev1.Container, podSecurityContext *corev1.PodSecurityContext, webhookConfig common.Config, secretInitConfig common.SecretInitConfig, vaultConfig vault.Config, initContainersMutated bool, containersMutated bool, containerEnvVars []corev1.EnvVar, containerVolMounts []corev1.VolumeMount) []corev1.Container {
	containers := []corev1.Container{}

	if vaultConfig.TokenAuthMount != "" {
		// secrets-webhook.security.bank-vaults.io/vault-token-auth-mount: "token:vault-token"
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
		serviceAccountMount := getServiceAccountMount(originalContainers, vaultConfig.ServiceAccountTokenVolumeName)

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

	if initContainersMutated || containersMutated && !isSecretInitContainerExists(originalContainers) {
		containers = append(containers, createCopySecretInitContainer(secretInitConfig, podSecurityContext, webhookConfig))
	}

	return containers
}

func (mw *MutatingWebhook) getVolumesForVault(existingVolumes []corev1.Volume, agentConfigMapName string, vaultConfig vault.Config) []corev1.Volume {
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
		if hasTLSVolume(existingVolumes, volumeName) {
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
				Name: "ct-secrets-vault",
				VolumeSource: corev1.VolumeSource{
					EmptyDir: &corev1.EmptyDirVolumeSource{
						Medium: corev1.StorageMediumMemory,
					},
				},
			},
			corev1.Volume{
				Name: "ct-configmap-vault",
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
				Name: "agent-secrets-vault",
				VolumeSource: corev1.VolumeSource{
					EmptyDir: &corev1.EmptyDirVolumeSource{
						Medium: corev1.StorageMediumMemory,
					},
				},
			},
			corev1.Volume{
				Name: "agent-configmap-vault",
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

func getAgentContainersForVault(originalContainers []corev1.Container, podSecurityContext *corev1.PodSecurityContext, webhookConfig common.Config, vaultConfig vault.Config, containerEnvVars []corev1.EnvVar, containerVolMounts []corev1.VolumeMount) []corev1.Container {
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

	serviceAccountMount := getServiceAccountMount(originalContainers, vaultConfig.ServiceAccountTokenVolumeName)

	containerVolMounts = append(containerVolMounts, serviceAccountMount, corev1.VolumeMount{
		Name:      "agent-secrets-vault",
		MountPath: vaultConfig.ConfigfilePath,
	}, corev1.VolumeMount{
		Name:      "agent-configmap-vault",
		MountPath: "/vault/config/config.hcl",
		ReadOnly:  true,
		SubPath:   "config.hcl",
	})

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

// ======== BAO ========

func (mw *MutatingWebhook) mutatePodForBao(ctx context.Context, pod *corev1.Pod, webhookConfig common.Config, secretInitConfig common.SecretInitConfig, baoConfig bao.Config, dryRun bool) error {
	initContainersMutated, err := mw.mutateContainers(ctx, pod.Spec.InitContainers, &pod.Spec, webhookConfig, secretInitConfig, baoConfig, baoConfig.ObjectNamespace, baoConfig.FromPath)
	if err != nil {
		return err
	}

	if initContainersMutated {
		mw.logger.Debug("Successfully mutated pod init containers")
	} else {
		mw.logger.Debug("No pod init containers were mutated")
	}

	containersMutated, err := mw.mutateContainers(ctx, pod.Spec.Containers, &pod.Spec, webhookConfig, secretInitConfig, baoConfig, baoConfig.ObjectNamespace, baoConfig.FromPath)
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
			Name:  "BAO_ADDR",
			Value: baoConfig.Addr,
		},
		{
			Name:  "BAO_SKIP_VERIFY",
			Value: strconv.FormatBool(baoConfig.SkipVerify),
		},
	}

	if baoConfig.Token != "" {
		containerEnvVars = append(containerEnvVars, corev1.EnvVar{
			Name:  "BAO_TOKEN",
			Value: baoConfig.Token,
		})
	}

	containerVolMounts := []corev1.VolumeMount{}
	if !isSecretInitAlreadyMounted(&pod.Spec) {
		containerVolMounts = []corev1.VolumeMount{
			{
				Name:      SecretInitVolumeName,
				MountPath: "/bank-vaults/",
			},
		}
	}

	if baoConfig.TLSSecret != "" {
		mountPath := "/bao/tls/"
		volumeName := "bao-tls"
		if hasTLSVolume(pod.Spec.Volumes, volumeName) {
			mountPath = "/secret-init/tls/"
			volumeName = "secret-init-tls"
		}

		containerEnvVars = append(containerEnvVars, corev1.EnvVar{
			Name:  "BAO_CACERT",
			Value: mountPath + "ca.crt",
		})

		containerVolMounts = append(containerVolMounts, corev1.VolumeMount{
			Name:      volumeName,
			MountPath: mountPath,
		})
	}

	if baoConfig.CtConfigMap != "" {
		mw.logger.Debug("Consul Template config found")

		mw.addSecretsVolToContainers(pod.Spec.Containers, baoConfig.ConfigfilePath)

		if baoConfig.CtShareProcessDefault == "empty" {
			mw.logger.Debug("Test our Kubernetes API Version and make the final decision on enabling ShareProcessNamespace")
			apiVersion, _ := mw.k8sClient.Discovery().ServerVersion()
			versionCompared := kubeVer.CompareKubeAwareVersionStrings("v1.12.0", apiVersion.String())
			mw.logger.Debug(fmt.Sprintf("Kubernetes API version detected: %s", apiVersion.String()))

			if versionCompared >= 0 {
				baoConfig.CtShareProcess = true
			} else {
				baoConfig.CtShareProcess = false
			}
		}

		if baoConfig.CtShareProcess {
			mw.logger.Debug("Detected shared process namespace")
			shareProcessNamespace := true
			pod.Spec.ShareProcessNamespace = &shareProcessNamespace
		}

		if !baoConfig.CtOnce {
			pod.Spec.Containers = append(getContainersForBao(pod.Spec.SecurityContext, webhookConfig, baoConfig, containerEnvVars, containerVolMounts), pod.Spec.Containers...)
		} else {
			if baoConfig.CtInjectInInitcontainers {
				mw.addSecretsVolToContainers(pod.Spec.InitContainers, baoConfig.ConfigfilePath)
			}
			pod.Spec.InitContainers = append(getContainersForBao(pod.Spec.SecurityContext, webhookConfig, baoConfig, containerEnvVars, containerVolMounts), pod.Spec.InitContainers...)
		}

		mw.logger.Debug("Successfully appended pod containers to spec")
	}

	if initContainersMutated || containersMutated || baoConfig.CtConfigMap != "" || baoConfig.AgentConfigMap != "" {
		var agentConfigMapName string

		if baoConfig.UseAgent || baoConfig.CtConfigMap != "" {
			if baoConfig.AgentConfigMap != "" {
				agentConfigMapName = baoConfig.AgentConfigMap
			} else {
				configMap := getConfigMapForBaoAgent(pod, baoConfig)
				agentConfigMapName = configMap.Name
				if !dryRun {
					_, err := mw.k8sClient.CoreV1().ConfigMaps(baoConfig.ObjectNamespace).Create(context.Background(), configMap, metav1.CreateOptions{})
					if err != nil {
						if apierrors.IsAlreadyExists(err) {
							_, err = mw.k8sClient.CoreV1().ConfigMaps(baoConfig.ObjectNamespace).Update(context.Background(), configMap, metav1.UpdateOptions{})
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

		pod.Spec.InitContainers = append(getInitContainersForBao(pod.Spec.Containers, pod.Spec.SecurityContext, webhookConfig, secretInitConfig, baoConfig, initContainersMutated, containersMutated, containerEnvVars, containerVolMounts), pod.Spec.InitContainers...)
		mw.logger.Debug("Successfully appended pod init containers to spec")

		pod.Spec.Volumes = append(pod.Spec.Volumes, mw.getVolumesForBao(pod.Spec.Volumes, agentConfigMapName, baoConfig)...)
		mw.logger.Debug("Successfully appended pod spec volumes")
	}

	if baoConfig.AgentConfigMap != "" && !baoConfig.UseAgent {
		mw.logger.Debug("Bao Agent config found")

		mw.addAgentSecretsVolToContainers(pod.Spec.Containers, baoConfig.ConfigfilePath)

		if baoConfig.AgentShareProcessDefault == "empty" {
			mw.logger.Debug("Test our Kubernetes API Version and make the final decision on enabling ShareProcessNamespace")
			apiVersion, _ := mw.k8sClient.Discovery().ServerVersion()
			versionCompared := kubeVer.CompareKubeAwareVersionStrings("v1.12.0", apiVersion.String())
			mw.logger.Debug(fmt.Sprintf("Kubernetes API version detected: %s", apiVersion.String()))

			if versionCompared >= 0 {
				baoConfig.AgentShareProcess = true
			} else {
				baoConfig.AgentShareProcess = false
			}
		}

		if baoConfig.AgentShareProcess {
			mw.logger.Debug("Detected shared process namespace")
			shareProcessNamespace := true
			pod.Spec.ShareProcessNamespace = &shareProcessNamespace
		}
		pod.Spec.Containers = append(getAgentContainersForBao(pod.Spec.Containers, pod.Spec.SecurityContext, webhookConfig, baoConfig, containerEnvVars, containerVolMounts), pod.Spec.Containers...)

		mw.logger.Debug("Successfully appended pod containers to spec")
	}

	return nil
}

func getContainersForBao(podSecurityContext *corev1.PodSecurityContext, webhookConfig common.Config, baoConfig bao.Config, containerEnvVars []corev1.EnvVar, containerVolMounts []corev1.VolumeMount) []corev1.Container {
	containers := []corev1.Container{}
	securityContext := getBaseSecurityContext(podSecurityContext, webhookConfig)

	if baoConfig.CtShareProcess {
		securityContext.Capabilities.Add = append(securityContext.Capabilities.Add, "SYS_PTRACE")
	}

	containerVolMounts = append(containerVolMounts, corev1.VolumeMount{
		Name:      "ct-secrets-bao",
		MountPath: baoConfig.ConfigfilePath,
	}, corev1.VolumeMount{
		Name:      SecretInitVolumeName,
		MountPath: "/home/consul-template-bao",
	}, corev1.VolumeMount{
		Name:      "ct-configmap-bao",
		MountPath: "/bao/ct-config/config.hcl",
		ReadOnly:  true,
		SubPath:   "config.hcl",
	})

	var ctCommandString []string
	if baoConfig.CtOnce {
		ctCommandString = []string{"-config", "/bao/ct-config/config.hcl", "-once"}
	} else {
		ctCommandString = []string{"-config", "/bao/ct-config/config.hcl"}
	}

	containers = append(containers, corev1.Container{
		Name:            "consul-template-bao",
		Image:           baoConfig.CtImage,
		Args:            ctCommandString,
		ImagePullPolicy: baoConfig.CtImagePullPolicy,
		SecurityContext: securityContext,
		Env:             containerEnvVars,
		VolumeMounts:    containerVolMounts,
		Resources: corev1.ResourceRequirements{
			Limits: corev1.ResourceList{
				corev1.ResourceCPU:    baoConfig.CtCPU,
				corev1.ResourceMemory: baoConfig.CtMemory,
			},
		},
	})

	return containers
}

func getConfigMapForBaoAgent(pod *corev1.Pod, baoConfig bao.Config) *corev1.ConfigMap {
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
			Name:            name + "-bao-agent-config",
			OwnerReferences: ownerReferences,
		},
		Data: map[string]string{
			"config.hcl": fmt.Sprintf(bao.AgentConfig, baoConfig.BaoNamespace, baoConfig.Path, baoConfig.Role),
		},
	}
}

func getInitContainersForBao(originalContainers []corev1.Container, podSecurityContext *corev1.PodSecurityContext, webhookConfig common.Config, secretInitConfig common.SecretInitConfig, baoConfig bao.Config, initContainersMutated bool, containersMutated bool, containerEnvVars []corev1.EnvVar, containerVolMounts []corev1.VolumeMount) []corev1.Container {
	containers := []corev1.Container{}

	if baoConfig.TokenAuthMount != "" {
		// secrets-webhook.security.bank-vaults.io/bao-token-auth-mount: "token:bao-token"
		split := strings.Split(baoConfig.TokenAuthMount, ":")
		mountName := split[0]
		tokenName := split[1]
		fileLoc := "/token/" + tokenName
		cmd := fmt.Sprintf("cp %s /bao/.bao-token", fileLoc)

		containers = append(containers, corev1.Container{
			Name:            "copy-bao-token",
			Image:           baoConfig.AgentImage,
			ImagePullPolicy: baoConfig.AgentImagePullPolicy,
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
	} else if baoConfig.Token == "" && (baoConfig.UseAgent || baoConfig.CtConfigMap != "") {
		serviceAccountMount := getServiceAccountMount(originalContainers, baoConfig.ServiceAccountTokenVolumeName)

		containerVolMounts = append(containerVolMounts, serviceAccountMount, corev1.VolumeMount{
			Name:      "bao-agent-config",
			MountPath: "/bao/agent/",
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
			Name:            "bao-agent",
			Image:           baoConfig.AgentImage,
			ImagePullPolicy: baoConfig.AgentImagePullPolicy,
			SecurityContext: securityContext,
			Command:         []string{"bao", "agent", "-config=/bao/agent/config.hcl", "-exit-after-auth"},
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

	if initContainersMutated || containersMutated && !isSecretInitContainerExists(originalContainers) {
		containers = append(containers, createCopySecretInitContainer(secretInitConfig, podSecurityContext, webhookConfig))
	}

	return containers
}

func (mw *MutatingWebhook) getVolumesForBao(existingVolumes []corev1.Volume, agentConfigMapName string, baoConfig bao.Config) []corev1.Volume {
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

	if baoConfig.UseAgent || baoConfig.CtConfigMap != "" {
		mw.logger.Debug("Add bao agent volumes to podspec")
		volumes = append(volumes, corev1.Volume{
			Name: "bao-agent-config",
			VolumeSource: corev1.VolumeSource{
				ConfigMap: &corev1.ConfigMapVolumeSource{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: agentConfigMapName,
					},
				},
			},
		})
	}

	if baoConfig.TLSSecret != "" {
		mw.logger.Debug("Add bao TLS volume to podspec")

		volumeName := "bao-tls"
		if hasTLSVolume(existingVolumes, volumeName) {
			volumeName = "secret-init-tls"
		}

		volumes = append(volumes, corev1.Volume{
			Name: volumeName,
			VolumeSource: corev1.VolumeSource{
				Projected: &corev1.ProjectedVolumeSource{
					Sources: []corev1.VolumeProjection{{
						Secret: &corev1.SecretProjection{
							LocalObjectReference: corev1.LocalObjectReference{
								Name: baoConfig.TLSSecret,
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
	if baoConfig.CtConfigMap != "" {
		mw.logger.Debug("Add consul template volumes to podspec")

		defaultMode := int32(420)
		volumes = append(volumes,
			corev1.Volume{
				Name: "ct-secrets-bao",
				VolumeSource: corev1.VolumeSource{
					EmptyDir: &corev1.EmptyDirVolumeSource{
						Medium: corev1.StorageMediumMemory,
					},
				},
			},
			corev1.Volume{
				Name: "ct-configmap-bao",
				VolumeSource: corev1.VolumeSource{
					ConfigMap: &corev1.ConfigMapVolumeSource{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: baoConfig.CtConfigMap,
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

	if baoConfig.AgentConfigMap != "" {
		mw.logger.Debug("Add bao-agent volumes to podspec")

		defaultMode := int32(420)
		volumes = append(volumes,
			corev1.Volume{
				Name: "agent-secrets-bao",
				VolumeSource: corev1.VolumeSource{
					EmptyDir: &corev1.EmptyDirVolumeSource{
						Medium: corev1.StorageMediumMemory,
					},
				},
			},
			corev1.Volume{
				Name: "agent-configmap-bao",
				VolumeSource: corev1.VolumeSource{
					ConfigMap: &corev1.ConfigMapVolumeSource{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: baoConfig.AgentConfigMap,
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

func getAgentContainersForBao(originalContainers []corev1.Container, podSecurityContext *corev1.PodSecurityContext, webhookConfig common.Config, baoConfig bao.Config, containerEnvVars []corev1.EnvVar, containerVolMounts []corev1.VolumeMount) []corev1.Container {
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

	if baoConfig.AgentShareProcess {
		securityContext.Capabilities.Add = append(securityContext.Capabilities.Add, "SYS_PTRACE")
	}

	serviceAccountMount := getServiceAccountMount(originalContainers, baoConfig.ServiceAccountTokenVolumeName)

	containerVolMounts = append(containerVolMounts, serviceAccountMount, corev1.VolumeMount{
		Name:      "agent-secrets-bao",
		MountPath: baoConfig.ConfigfilePath,
	}, corev1.VolumeMount{
		Name:      "agent-configmap-bao",
		MountPath: "/bao/config/config.hcl",
		ReadOnly:  true,
		SubPath:   "config.hcl",
	})

	var agentCommandString []string
	if baoConfig.AgentOnce {
		agentCommandString = []string{"agent", "-config", "/bao/config/config.hcl", "-exit-after-auth"}
	} else {
		agentCommandString = []string{"agent", "-config", "/bao/config/config.hcl"}
	}

	if baoConfig.AgentEnvVariables != "" {
		var envVars []corev1.EnvVar
		err := json.Unmarshal([]byte(baoConfig.AgentEnvVariables), &envVars)
		if err != nil {
			envVars = []corev1.EnvVar{}
		}
		containerEnvVars = append(containerEnvVars, envVars...)
	}

	containers = append(containers, corev1.Container{
		Name:            "bao-agent",
		Image:           baoConfig.AgentImage,
		Args:            agentCommandString,
		ImagePullPolicy: baoConfig.AgentImagePullPolicy,
		SecurityContext: securityContext,
		Env:             containerEnvVars,
		VolumeMounts:    containerVolMounts,
		Resources: corev1.ResourceRequirements{
			Limits: corev1.ResourceList{
				corev1.ResourceCPU:    baoConfig.AgentCPULimit,
				corev1.ResourceMemory: baoConfig.AgentMemoryLimit,
			},
			Requests: corev1.ResourceList{
				corev1.ResourceCPU:    baoConfig.AgentCPURequest,
				corev1.ResourceMemory: baoConfig.AgentMemoryRequest,
			},
		},
	})

	return containers
}
