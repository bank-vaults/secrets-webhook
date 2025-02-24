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
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"emperror.dev/errors"
	secretInitCommon "github.com/bank-vaults/secret-init/pkg/common"
	baoinjector "github.com/bank-vaults/vault-sdk/injector/bao"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kubeVer "k8s.io/apimachinery/pkg/version"
	"k8s.io/client-go/kubernetes"

	appCommon "github.com/bank-vaults/secrets-webhook/pkg/common"
	"github.com/bank-vaults/secrets-webhook/pkg/provider"
	"github.com/bank-vaults/secrets-webhook/pkg/provider/common"
	"github.com/bank-vaults/secrets-webhook/pkg/registry"
)

func (m *mutator) MutatePod(ctx context.Context, mutateRequest provider.PodMutateRequest) error {
	m.logger.Debug("Successfully connected to the API")

	if common.IsPodAlreadyMutated(mutateRequest.Pod) {
		m.logger.Info(fmt.Sprintf("Pod %s is already mutated, skipping mutation.", mutateRequest.Pod.Name))
		return nil
	}

	initContainersMutated, err := m.MutateContainers(ctx, mutateRequest.Pod.Spec.InitContainers, &mutateRequest.Pod.Spec, mutateRequest.WebhookConfig, mutateRequest.SecretInitConfig, mutateRequest.K8sClient, mutateRequest.Registry)
	if err != nil {
		return err
	}

	if initContainersMutated {
		m.logger.Debug("Successfully mutated pod init containers")
	} else {
		m.logger.Debug("No pod init containers were mutated")
	}

	containersMutated, err := m.MutateContainers(ctx, mutateRequest.Pod.Spec.Containers, &mutateRequest.Pod.Spec, mutateRequest.WebhookConfig, mutateRequest.SecretInitConfig, mutateRequest.K8sClient, mutateRequest.Registry)
	if err != nil {
		return err
	}

	if containersMutated {
		m.logger.Debug("Successfully mutated pod containers")
	} else {
		m.logger.Debug("No pod containers were mutated")
	}

	containerEnvVars := []corev1.EnvVar{
		{
			Name:  "BAO_ADDR",
			Value: m.config.Addr,
		},
		{
			Name:  "BAO_SKIP_VERIFY",
			Value: strconv.FormatBool(m.config.SkipVerify),
		},
	}

	if m.config.Token != "" {
		containerEnvVars = append(containerEnvVars, corev1.EnvVar{
			Name:  "BAO_TOKEN",
			Value: m.config.Token,
		})
	}

	containerVolMounts := []corev1.VolumeMount{
		{
			Name:      common.SecretInitVolumeName,
			MountPath: "/bao/",
		},
	}
	if m.config.TLSSecret != "" {
		mountPath := "/bao/tls/"
		volumeName := "bao-tls"
		if common.HasTLSVolume(mutateRequest.Pod.Spec.Volumes, volumeName) {
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

	if m.config.CtConfigMap != "" {
		m.logger.Debug("Consul Template config found")

		m.addSecretsVolToContainers(mutateRequest.Pod.Spec.Containers)

		if m.config.CtShareProcessDefault == "empty" {
			m.logger.Debug("Test our Kubernetes API Version and make the final decision on enabling ShareProcessNamespace")
			apiVersion, _ := mutateRequest.K8sClient.Discovery().ServerVersion()
			versionCompared := kubeVer.CompareKubeAwareVersionStrings("v1.12.0", apiVersion.String())
			m.logger.Debug(fmt.Sprintf("Kubernetes API version detected: %s", apiVersion.String()))

			if versionCompared >= 0 {
				m.config.CtShareProcess = true
			} else {
				m.config.CtShareProcess = false
			}
		}

		if m.config.CtShareProcess {
			m.logger.Debug("Detected shared process namespace")
			shareProcessNamespace := true
			mutateRequest.Pod.Spec.ShareProcessNamespace = &shareProcessNamespace
		}
		if !m.config.CtOnce {
			mutateRequest.Pod.Spec.Containers = append(m.getContainers(mutateRequest.Pod.Spec.SecurityContext, mutateRequest.WebhookConfig, containerEnvVars, containerVolMounts), mutateRequest.Pod.Spec.Containers...)
		} else {
			if m.config.CtInjectInInitcontainers {
				m.addSecretsVolToContainers(mutateRequest.Pod.Spec.InitContainers)
			}

			mutateRequest.Pod.Spec.InitContainers = append(m.getContainers(mutateRequest.Pod.Spec.SecurityContext, mutateRequest.WebhookConfig, containerEnvVars, containerVolMounts), mutateRequest.Pod.Spec.InitContainers...)
		}

		m.logger.Debug("Successfully appended pod containers to spec")
	}

	if initContainersMutated || containersMutated || m.config.CtConfigMap != "" || m.config.AgentConfigMap != "" {
		var agentConfigMapName string

		if m.config.UseAgent || m.config.CtConfigMap != "" {
			if m.config.AgentConfigMap != "" {
				agentConfigMapName = m.config.AgentConfigMap
			} else {
				configMap := m.getConfigMapForBaoAgent(mutateRequest.Pod)
				agentConfigMapName = configMap.Name
				if !mutateRequest.DryRun {
					_, err := mutateRequest.K8sClient.CoreV1().ConfigMaps(m.config.ObjectNamespace).Create(ctx, configMap, metav1.CreateOptions{})
					if err != nil {
						if apierrors.IsAlreadyExists(err) {
							_, err = mutateRequest.K8sClient.CoreV1().ConfigMaps(m.config.ObjectNamespace).Update(ctx, configMap, metav1.UpdateOptions{})
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

		mutateRequest.Pod.Spec.InitContainers = append(m.getInitContainers(mutateRequest.Pod.Spec.Containers, mutateRequest.Pod.Spec.SecurityContext, mutateRequest.WebhookConfig, mutateRequest.SecretInitConfig, initContainersMutated, containersMutated, containerEnvVars, containerVolMounts), mutateRequest.Pod.Spec.InitContainers...)
		m.logger.Debug("Successfully appended pod init containers to spec")

		mutateRequest.Pod.Spec.Volumes = append(mutateRequest.Pod.Spec.Volumes, m.getVolumes(mutateRequest.Pod.Spec.Volumes, agentConfigMapName)...)
		m.logger.Debug("Successfully appended pod spec volumes")
	}

	if m.config.AgentConfigMap != "" && m.config.UseAgent {
		m.addAgentSecretsVolToContainers(mutateRequest.Pod.Spec.Containers)
	}

	if m.config.AgentConfigMap != "" && !m.config.UseAgent {
		m.logger.Debug("Bao Agent config found")

		m.addAgentSecretsVolToContainers(mutateRequest.Pod.Spec.Containers)

		if m.config.AgentShareProcessDefault == "empty" {
			m.logger.Debug("Test our Kubernetes API Version and make the final decision on enabling ShareProcessNamespace")
			apiVersion, _ := mutateRequest.K8sClient.Discovery().ServerVersion()
			versionCompared := kubeVer.CompareKubeAwareVersionStrings("v1.12.0", apiVersion.String())
			m.logger.Debug(fmt.Sprintf("Kubernetes API version detected: %s", apiVersion.String()))

			if versionCompared >= 0 {
				m.config.AgentShareProcess = true
			} else {
				m.config.AgentShareProcess = false
			}
		}

		if m.config.AgentShareProcess {
			m.logger.Debug("Detected shared process namespace")
			shareProcessNamespace := true
			mutateRequest.Pod.Spec.ShareProcessNamespace = &shareProcessNamespace
		}
		mutateRequest.Pod.Spec.Containers = append(m.getAgentContainers(mutateRequest.Pod.Spec.Containers, mutateRequest.Pod.Spec.SecurityContext, mutateRequest.WebhookConfig, containerEnvVars, containerVolMounts), mutateRequest.Pod.Spec.Containers...)

		m.logger.Debug("Successfully appended pod containers to spec")
	}

	return nil
}

func (m *mutator) MutateContainers(ctx context.Context, containers []corev1.Container, podSpec *corev1.PodSpec, webhookConfig appCommon.Config, secretInitConfig appCommon.SecretInitConfig, k8sClient kubernetes.Interface, registry registry.ImageRegistry) (bool, error) {
	mutated := false

	for i, container := range containers {
		var envVars []corev1.EnvVar
		if len(container.EnvFrom) > 0 {
			envFrom, err := lookForEnvFrom(ctx, k8sClient, container.EnvFrom, m.config.ObjectNamespace)
			if err != nil {
				return false, err
			}

			envVars = append(envVars, envFrom...)
		}

		for _, env := range container.Env {
			if isValidPrefix(env.Value) || baoinjector.HasInlineBaoDelimiters(env.Value) {
				envVars = append(envVars, env)
			}
			if env.ValueFrom != nil {
				valueFrom, err := lookForValueFrom(ctx, k8sClient, env, m.config.ObjectNamespace)
				if err != nil {
					return false, err
				}
				if valueFrom == nil {
					continue
				}

				envVars = append(envVars, *valueFrom)
			}
		}

		if len(envVars) == 0 && m.config.FromPath == "" {
			continue
		}

		mutated = true

		args := container.Command

		// the container has no explicitly specified command
		if len(args) == 0 {
			imageConfig, err := registry.GetImageConfig(ctx, k8sClient, m.config.ObjectNamespace, webhookConfig.RegistrySkipVerify, &container, podSpec) //nolint:gosec
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

		container.Command = []string{"/bao/secret-init"}
		container.Args = args

		if webhookConfig.MutateProbes {
			if container.LivenessProbe != nil && container.LivenessProbe.Exec != nil {
				lProbeCmd := container.LivenessProbe.Exec.Command
				container.LivenessProbe.Exec.Command = []string{"/bao/secret-init"}
				container.LivenessProbe.Exec.Command = append(container.LivenessProbe.Exec.Command, lProbeCmd...)
			}
			if container.ReadinessProbe != nil && container.ReadinessProbe.Exec != nil {
				rProbeCmd := container.ReadinessProbe.Exec.Command
				container.ReadinessProbe.Exec.Command = []string{"/bao/secret-init"}
				container.ReadinessProbe.Exec.Command = append(container.ReadinessProbe.Exec.Command, rProbeCmd...)
			}
			if container.StartupProbe != nil && container.StartupProbe.Exec != nil {
				sProbeCmd := container.StartupProbe.Exec.Command
				container.StartupProbe.Exec.Command = []string{"/bao/secret-init"}
				container.StartupProbe.Exec.Command = append(container.StartupProbe.Exec.Command, sProbeCmd...)
			}
		}

		container.VolumeMounts = append(container.VolumeMounts, []corev1.VolumeMount{
			{
				Name:      common.SecretInitVolumeName,
				MountPath: "/bao/",
			},
		}...)

		container.Env = append(container.Env, []corev1.EnvVar{
			{
				Name:  "BAO_ADDR",
				Value: m.config.Addr,
			},
			{
				Name:  "BAO_SKIP_VERIFY",
				Value: strconv.FormatBool(m.config.SkipVerify),
			},
			{
				Name:  "BAO_AUTH_METHOD",
				Value: m.config.AuthMethod,
			},
			{
				Name:  "BAO_PATH",
				Value: m.config.Path,
			},
			{
				Name:  "BAO_ROLE",
				Value: m.config.Role,
			},
			{
				Name:  "BAO_IGNORE_MISSING_SECRETS",
				Value: m.config.IgnoreMissingSecrets,
			},
			{
				Name:  "BAO_PASSTHROUGH",
				Value: m.config.Passthrough,
			},
			{
				Name:  secretInitCommon.JSONLogEnv,
				Value: secretInitConfig.JSONLog,
			},
			{
				Name:  "BAO_CLIENT_TIMEOUT",
				Value: m.config.ClientTimeout.String(),
			},
		}...)

		if m.config.Token != "" {
			container.Env = append(container.Env, corev1.EnvVar{
				Name:  "BAO_TOKEN",
				Value: m.config.Token,
			})
		}

		if !common.IsLogLevelSet(container.Env) && secretInitConfig.LogLevel != "" {
			container.Env = append(container.Env, []corev1.EnvVar{
				{
					Name:  secretInitCommon.LogLevelEnv,
					Value: secretInitConfig.LogLevel,
				},
			}...)
		}

		if len(m.config.TransitKeyID) > 0 {
			container.Env = append(container.Env, []corev1.EnvVar{
				{
					Name:  "BAO_TRANSIT_KEY_ID",
					Value: m.config.TransitKeyID,
				},
			}...)
		}

		if len(m.config.TransitPath) > 0 {
			container.Env = append(container.Env, []corev1.EnvVar{
				{
					Name:  "BAO_TRANSIT_PATH",
					Value: m.config.TransitPath,
				},
			}...)
		}

		if m.config.TransitBatchSize > 0 {
			container.Env = append(container.Env, []corev1.EnvVar{
				{
					Name:  "BAO_TRANSIT_BATCH_SIZE",
					Value: strconv.Itoa(m.config.TransitBatchSize),
				},
			}...)
		}

		if len(m.config.BaoNamespace) > 0 {
			container.Env = append(container.Env, []corev1.EnvVar{
				{
					Name:  "BAO_NAMESPACE",
					Value: m.config.BaoNamespace,
				},
			}...)
		}

		if m.config.TLSSecret != "" {
			mountPath := "/bao/tls/"
			volumeName := "bao-tls"
			if common.HasTLSVolume(podSpec.Volumes, volumeName) {
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

		if m.config.UseAgent || m.config.TokenAuthMount != "" {
			container.Env = append(container.Env, corev1.EnvVar{
				Name:  "BAO_TOKEN_FILE",
				Value: "/bao/.bao-token",
			})
		}

		if secretInitConfig.Daemon {
			container.Env = append(container.Env, corev1.EnvVar{
				Name:  secretInitCommon.DaemonEnv,
				Value: "true",
			})
		}

		if secretInitConfig.Delay > 0 {
			container.Env = append(container.Env, corev1.EnvVar{
				Name:  secretInitCommon.DelayEnv,
				Value: secretInitConfig.Delay.String(),
			})
		}

		if m.config.FromPath != "" {
			container.Env = append(container.Env, corev1.EnvVar{
				Name:  "BAO_FROM_PATH",
				Value: m.config.FromPath,
			})
		}

		if secretInitConfig.LogServer != "" {
			container.Env = append(container.Env, corev1.EnvVar{
				Name:  secretInitCommon.LogServerEnv,
				Value: secretInitConfig.LogServer,
			})
		}

		containers[i] = container
	}

	return mutated, nil
}

func lookForEnvFrom(ctx context.Context, k8sClient kubernetes.Interface, envFrom []corev1.EnvFromSource, ns string) ([]corev1.EnvVar, error) {
	var envVars []corev1.EnvVar

	for _, ef := range envFrom {
		if ef.ConfigMapRef != nil {
			data, err := common.GetDataFromConfigmap(ctx, k8sClient, ef.ConfigMapRef.Name, ns)
			if err != nil {
				if apierrors.IsNotFound(err) || (ef.ConfigMapRef.Optional != nil && *ef.ConfigMapRef.Optional) {
					continue
				}

				return envVars, err
			}

			for key, value := range data {
				if isValidPrefix(value) || baoinjector.HasInlineBaoDelimiters(value) {
					envFromCM := corev1.EnvVar{
						Name:  key,
						Value: value,
					}

					envVars = append(envVars, envFromCM)
				}
			}
		}

		if ef.SecretRef != nil {
			data, err := common.GetDataFromSecret(ctx, k8sClient, ef.SecretRef.Name, ns)
			if err != nil {
				if apierrors.IsNotFound(err) || (ef.SecretRef.Optional != nil && *ef.SecretRef.Optional) {
					continue
				}

				return envVars, err
			}

			for name, v := range data {
				value := string(v)
				if isValidPrefix(value) || baoinjector.HasInlineBaoDelimiters(value) {
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

func lookForValueFrom(ctx context.Context, k8sClient kubernetes.Interface, env corev1.EnvVar, ns string) (*corev1.EnvVar, error) {
	if env.ValueFrom.ConfigMapKeyRef != nil {
		data, err := common.GetDataFromConfigmap(ctx, k8sClient, env.ValueFrom.ConfigMapKeyRef.Name, ns)
		if err != nil {
			if apierrors.IsNotFound(err) {
				return nil, nil
			}

			return nil, err
		}

		value := data[env.ValueFrom.ConfigMapKeyRef.Key]
		if isValidPrefix(value) || baoinjector.HasInlineBaoDelimiters(value) {
			fromCM := corev1.EnvVar{
				Name:  env.Name,
				Value: value,
			}

			return &fromCM, nil
		}
	}

	if env.ValueFrom.SecretKeyRef != nil {
		data, err := common.GetDataFromSecret(ctx, k8sClient, env.ValueFrom.SecretKeyRef.Name, ns)
		if err != nil {
			if apierrors.IsNotFound(err) {
				return nil, nil
			}

			return nil, err
		}

		value := string(data[env.ValueFrom.SecretKeyRef.Key])
		if isValidPrefix(value) || baoinjector.HasInlineBaoDelimiters(value) {
			fromSecret := corev1.EnvVar{
				Name:  env.Name,
				Value: value,
			}

			return &fromSecret, nil
		}
	}

	return nil, nil
}

func (m *mutator) addSecretsVolToContainers(containers []corev1.Container) {
	for i, container := range containers {
		m.logger.Debug(fmt.Sprintf("Add secrets VolumeMount to container %s", container.Name))

		container.VolumeMounts = append(container.VolumeMounts, []corev1.VolumeMount{
			{
				Name:      "ct-secrets",
				MountPath: m.config.ConfigfilePath,
			},
		}...)

		containers[i] = container
	}
}

func (m *mutator) getInitContainers(originalContainers []corev1.Container, podSecurityContext *corev1.PodSecurityContext, webhookConfig appCommon.Config, secretInitConfig appCommon.SecretInitConfig, initContainersMutated bool, containersMutated bool, containerEnvVars []corev1.EnvVar, containerVolMounts []corev1.VolumeMount) []corev1.Container {
	containers := []corev1.Container{}

	if m.config.TokenAuthMount != "" {
		// secrets-webhook.security.bank-vaults.io/bao-token-auth-mount: "token:bao-token"
		split := strings.Split(m.config.TokenAuthMount, ":")
		mountName := split[0]
		tokenName := split[1]
		fileLoc := "/token/" + tokenName
		cmd := fmt.Sprintf("cp %s /bao/.bao-token", fileLoc)

		containers = append(containers, corev1.Container{
			Name:            "copy-bao-token",
			Image:           m.config.AgentImage,
			ImagePullPolicy: m.config.AgentImagePullPolicy,
			Command:         []string{"sh", "-c", cmd},
			SecurityContext: common.GetBaseSecurityContext(podSecurityContext, webhookConfig),
			Resources: corev1.ResourceRequirements{
				Limits: corev1.ResourceList{
					corev1.ResourceCPU:    resource.MustParse("50m"),
					corev1.ResourceMemory: resource.MustParse("64Mi"),
				},
			},
			VolumeMounts: []corev1.VolumeMount{
				{
					Name:      common.SecretInitVolumeName,
					MountPath: "/bao/",
				},
				{
					Name:      mountName,
					MountPath: "/token",
				},
			},
		})
	} else if m.config.Token == "" && (m.config.UseAgent || m.config.CtConfigMap != "") {
		serviceAccountMount := common.GetServiceAccountMount(originalContainers, m.config.ServiceAccountTokenVolumeName)

		containerVolMounts = append(containerVolMounts, serviceAccountMount, corev1.VolumeMount{
			Name:      "bao-agent-config",
			MountPath: "/bao/agent/",
		})

		if m.config.CtConfigMap == "" {
			containerVolMounts = append(containerVolMounts, corev1.VolumeMount{
				Name:      "agent-secrets",
				MountPath: m.config.ConfigfilePath,
			})
		}

		securityContext := common.GetBaseSecurityContext(podSecurityContext, webhookConfig)
		securityContext.Capabilities.Add = []corev1.Capability{
			"CHOWN",
			"SETFCAP",
			"SETGID",
			"SETPCAP",
			"SETUID",
		}

		containers = append(containers, corev1.Container{
			Name:            "bao-agent",
			Image:           m.config.AgentImage,
			ImagePullPolicy: m.config.AgentImagePullPolicy,
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

	if initContainersMutated || containersMutated {
		containers = append(containers, corev1.Container{
			Name:            "copy-secret-init",
			Image:           secretInitConfig.Image,
			ImagePullPolicy: secretInitConfig.ImagePullPolicy,
			Command:         []string{"sh", "-c", "cp /usr/local/bin/secret-init /bao/"},
			VolumeMounts: []corev1.VolumeMount{
				{
					Name:      common.SecretInitVolumeName,
					MountPath: "/bao/",
				},
			},

			SecurityContext: common.GetBaseSecurityContext(podSecurityContext, webhookConfig),
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

func (m *mutator) getContainers(podSecurityContext *corev1.PodSecurityContext, webhookConfig appCommon.Config, containerEnvVars []corev1.EnvVar, containerVolMounts []corev1.VolumeMount) []corev1.Container {
	containers := []corev1.Container{}
	securityContext := common.GetBaseSecurityContext(podSecurityContext, webhookConfig)

	if m.config.CtShareProcess {
		securityContext.Capabilities.Add = append(securityContext.Capabilities.Add, "SYS_PTRACE")
	}

	containerVolMounts = append(containerVolMounts, corev1.VolumeMount{
		Name:      "ct-secrets",
		MountPath: m.config.ConfigfilePath,
	}, corev1.VolumeMount{
		Name:      common.SecretInitVolumeName,
		MountPath: "/home/consul-template",
	}, corev1.VolumeMount{
		Name:      "ct-configmap",
		MountPath: "/bao/ct-config/config.hcl",
		ReadOnly:  true,
		SubPath:   "config.hcl",
	},
	)

	var ctCommandString []string
	if m.config.CtOnce {
		ctCommandString = []string{"-config", "/bao/ct-config/config.hcl", "-once"}
	} else {
		ctCommandString = []string{"-config", "/bao/ct-config/config.hcl"}
	}

	containers = append(containers, corev1.Container{
		Name:            "consul-template",
		Image:           m.config.CtImage,
		Args:            ctCommandString,
		ImagePullPolicy: m.config.CtImagePullPolicy,
		SecurityContext: securityContext,
		Env:             containerEnvVars,
		VolumeMounts:    containerVolMounts,
		Resources: corev1.ResourceRequirements{
			Limits: corev1.ResourceList{
				corev1.ResourceCPU:    m.config.CtCPU,
				corev1.ResourceMemory: m.config.CtMemory,
			},
		},
	})

	return containers
}

func (m *mutator) getConfigMapForBaoAgent(pod *corev1.Pod) *corev1.ConfigMap {
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
			"config.hcl": fmt.Sprintf(AgentConfig, m.config.BaoNamespace, m.config.Path, m.config.Role),
		},
	}
}

func (m *mutator) getVolumes(existingVolumes []corev1.Volume, agentConfigMapName string) []corev1.Volume {
	m.logger.Debug("Add generic volumes to podspec")

	volumes := []corev1.Volume{
		{
			Name: common.SecretInitVolumeName,
			VolumeSource: corev1.VolumeSource{
				EmptyDir: &corev1.EmptyDirVolumeSource{
					Medium: corev1.StorageMediumMemory,
				},
			},
		},
	}

	if m.config.UseAgent || m.config.CtConfigMap != "" {
		m.logger.Debug("Add bao agent volumes to podspec")
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

	if m.config.TLSSecret != "" {
		m.logger.Debug("Add bao TLS volume to podspec")

		volumeName := "bao-tls"
		if common.HasTLSVolume(existingVolumes, volumeName) {
			volumeName = "secret-init-tls"
		}

		volumes = append(volumes, corev1.Volume{
			Name: volumeName,
			VolumeSource: corev1.VolumeSource{
				Projected: &corev1.ProjectedVolumeSource{
					Sources: []corev1.VolumeProjection{{
						Secret: &corev1.SecretProjection{
							LocalObjectReference: corev1.LocalObjectReference{
								Name: m.config.TLSSecret,
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

	if m.config.CtConfigMap != "" {
		m.logger.Debug("Add consul template volumes to podspec")

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
							Name: m.config.CtConfigMap,
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

	if m.config.AgentConfigMap != "" {
		m.logger.Debug("Add bao-agent volumes to podspec")

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
							Name: m.config.AgentConfigMap,
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

func (m *mutator) addAgentSecretsVolToContainers(containers []corev1.Container) {
	for i, container := range containers {
		m.logger.Debug(fmt.Sprintf("Add secrets VolumeMount to container %s", container.Name))

		container.VolumeMounts = append(container.VolumeMounts, []corev1.VolumeMount{
			{
				Name:      "agent-secrets",
				MountPath: m.config.ConfigfilePath,
			},
		}...)

		containers[i] = container
	}
}

func (m *mutator) getAgentContainers(originalContainers []corev1.Container, podSecurityContext *corev1.PodSecurityContext, webhookConfig appCommon.Config, containerEnvVars []corev1.EnvVar, containerVolMounts []corev1.VolumeMount) []corev1.Container {
	containers := []corev1.Container{}

	securityContext := common.GetBaseSecurityContext(podSecurityContext, webhookConfig)
	securityContext.Capabilities.Add = []corev1.Capability{
		"CHOWN",
		"SETFCAP",
		"SETGID",
		"SETPCAP",
		"SETUID",
		"IPC_LOCK",
	}

	if m.config.AgentShareProcess {
		securityContext.Capabilities.Add = append(securityContext.Capabilities.Add, "SYS_PTRACE")
	}

	serviceAccountMount := common.GetServiceAccountMount(originalContainers, m.config.ServiceAccountTokenVolumeName)

	containerVolMounts = append(containerVolMounts, serviceAccountMount, corev1.VolumeMount{
		Name:      "agent-secrets",
		MountPath: m.config.ConfigfilePath,
	}, corev1.VolumeMount{
		Name:      "agent-configmap",
		MountPath: "/bao/config/config.hcl",
		ReadOnly:  true,
		SubPath:   "config.hcl",
	},
	)

	var agentCommandString []string
	if m.config.AgentOnce {
		agentCommandString = []string{"agent", "-config", "/bao/config/config.hcl", "-exit-after-auth"}
	} else {
		agentCommandString = []string{"agent", "-config", "/bao/config/config.hcl"}
	}

	if m.config.AgentEnvVariables != "" {
		var envVars []corev1.EnvVar
		err := json.Unmarshal([]byte(m.config.AgentEnvVariables), &envVars)
		if err != nil {
			envVars = []corev1.EnvVar{}
		}

		containerEnvVars = append(containerEnvVars, envVars...)
	}

	containers = append(containers, corev1.Container{
		Name:            "bao-agent",
		Image:           m.config.AgentImage,
		Args:            agentCommandString,
		ImagePullPolicy: m.config.AgentImagePullPolicy,
		SecurityContext: securityContext,
		Env:             containerEnvVars,
		VolumeMounts:    containerVolMounts,
		Resources: corev1.ResourceRequirements{
			Limits: corev1.ResourceList{
				corev1.ResourceCPU:    m.config.AgentCPULimit,
				corev1.ResourceMemory: m.config.AgentMemoryLimit,
			},
			Requests: corev1.ResourceList{
				corev1.ResourceCPU:    m.config.AgentCPURequest,
				corev1.ResourceMemory: m.config.AgentMemoryRequest,
			},
		},
	})

	return containers
}
