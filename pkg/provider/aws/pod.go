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

package aws

import (
	"bytes"
	"context"
	"encoding/pem"
	"fmt"
	"strconv"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/acm"
	secretInitCommon "github.com/bank-vaults/secret-init/pkg/common"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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
		return fmt.Errorf("failed to mutate pod init containers: %w", err)
	}

	if initContainersMutated {
		m.logger.Debug("Successfully mutated pod init containers")
	} else {
		m.logger.Debug("No pod init containers were mutated")
	}

	containersMutated, err := m.MutateContainers(ctx, mutateRequest.Pod.Spec.Containers, &mutateRequest.Pod.Spec, mutateRequest.WebhookConfig, mutateRequest.SecretInitConfig, mutateRequest.K8sClient, mutateRequest.Registry)
	if err != nil {
		return fmt.Errorf("failed to mutate pod containers: %w", err)
	}

	if containersMutated {
		m.logger.Debug("Successfully mutated pod containers")
	} else {
		m.logger.Debug("No pod containers were mutated")
	}

	if initContainersMutated || containersMutated {
		mutateRequest.Pod.Spec.InitContainers = append(m.addInitContainerForSecretInit(mutateRequest.Pod.Spec.SecurityContext, mutateRequest.WebhookConfig, mutateRequest.SecretInitConfig), mutateRequest.Pod.Spec.InitContainers...)
		m.logger.Debug("Successfully appended Secret-Init container to spec")

		mutateRequest.Pod.Spec.Volumes = append(m.addVolumes(mutateRequest.Pod.Spec.Volumes), mutateRequest.Pod.Spec.Volumes...)
		m.logger.Debug("Successfully appended empty-dir volume for Secret-Init to spec")
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
				return false, fmt.Errorf("failed to look for envFrom: %w", err)
			}

			envVars = append(envVars, envFrom...)
		}

		for _, env := range container.Env {
			if isValidPrefix(env.Value) {
				envVars = append(envVars, env)
			}
			if env.ValueFrom != nil {
				valueFrom, err := lookForValueFrom(ctx, k8sClient, env, m.config.ObjectNamespace)
				if err != nil {
					return false, fmt.Errorf("failed to look for valueFrom: %w", err)
				}
				if valueFrom == nil {
					continue
				}

				envVars = append(envVars, *valueFrom)
			}
		}

		if len(envVars) == 0 {
			continue
		}

		mutated = true

		args := container.Command

		// the container has no explicitly specified command
		if len(args) == 0 {
			imageConfig, err := registry.GetImageConfig(ctx, k8sClient, m.config.ObjectNamespace, webhookConfig.RegistrySkipVerify, &container, podSpec) //nolint:gosec
			if err != nil {
				return false, fmt.Errorf("failed to get image config: %w", err)
			}

			args = append(args, imageConfig.Entrypoint...)

			// If no Args are defined we can use the Docker CMD from the image
			// https://kubernetes.io/docs/tasks/inject-data-application/define-command-argument-container/#notes
			if len(container.Args) == 0 {
				args = append(args, imageConfig.Cmd...)
			}
		}

		args = append(args, container.Args...)

		container.Command = []string{"/aws/secret-init"}
		container.Args = args

		if webhookConfig.MutateProbes {
			if container.LivenessProbe != nil && container.LivenessProbe.Exec != nil {
				lProbeCmd := container.LivenessProbe.Exec.Command
				container.LivenessProbe.Exec.Command = []string{"/aws/secret-init"}
				container.LivenessProbe.Exec.Command = append(container.LivenessProbe.Exec.Command, lProbeCmd...)
			}
			if container.ReadinessProbe != nil && container.ReadinessProbe.Exec != nil {
				rProbeCmd := container.ReadinessProbe.Exec.Command
				container.ReadinessProbe.Exec.Command = []string{"/aws/secret-init"}
				container.ReadinessProbe.Exec.Command = append(container.ReadinessProbe.Exec.Command, rProbeCmd...)
			}
			if container.StartupProbe != nil && container.StartupProbe.Exec != nil {
				sProbeCmd := container.StartupProbe.Exec.Command
				container.StartupProbe.Exec.Command = []string{"/aws/secret-init"}
				container.StartupProbe.Exec.Command = append(container.StartupProbe.Exec.Command, sProbeCmd...)
			}
		}

		container.VolumeMounts = append(container.VolumeMounts, []corev1.VolumeMount{
			{
				Name:      common.SecretInitVolumeName,
				MountPath: "/aws/",
			},
		}...)

		container.Env = append(container.Env, []corev1.EnvVar{
			{
				Name:  "AWS_REGION",
				Value: m.config.Region,
			},
			{
				Name:  secretInitCommon.JSONLogEnv,
				Value: secretInitConfig.JSONLog,
			},
			{
				Name:  "AWS_LOAD_FROM_SHARED_CONFIG",
				Value: strconv.FormatBool(m.config.LoadFromSharedConfig),
			},
		}...)

		if !common.IsLogLevelSet(container.Env) && secretInitConfig.LogLevel != "" {
			container.Env = append(container.Env, []corev1.EnvVar{
				{
					Name:  secretInitCommon.LogLevelEnv,
					Value: secretInitConfig.LogLevel,
				},
			}...)
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

		if secretInitConfig.LogServer != "" {
			container.Env = append(container.Env, corev1.EnvVar{
				Name:  secretInitCommon.LogServerEnv,
				Value: secretInitConfig.LogServer,
			})
		}

		sess, err := m.createAWSSession(ctx, k8sClient)
		if err != nil {
			return false, fmt.Errorf("failed to create AWS session: %w", err)
		}

		creds, err := sess.Config.Credentials.GetWithContext(ctx)
		if err != nil {
			return false, fmt.Errorf("failed to get AWS credentials: %w", err)
		}

		if creds.AccessKeyID != "" {
			container.Env = append(container.Env, corev1.EnvVar{
				Name:  "AWS_ACCESS_KEY_ID",
				Value: creds.AccessKeyID,
			})
		}

		if creds.SecretAccessKey != "" {
			container.Env = append(container.Env, corev1.EnvVar{
				Name:  "AWS_SECRET_ACCESS_KEY",
				Value: creds.SecretAccessKey,
			})
		}

		if creds.SessionToken != "" {
			container.Env = append(container.Env, corev1.EnvVar{
				Name:  "AWS_SESSION_TOKEN",
				Value: creds.SessionToken,
			})
		}

		if m.config.TLSSecretARN != "" {
			cert, err := acm.New(sess).GetCertificate(&acm.GetCertificateInput{
				CertificateArn: aws.String(m.config.TLSSecretARN),
			})
			if err != nil {
				return false, fmt.Errorf("failed to get certificate: %w", err)
			}

			pemBuffer, err := encodeCertificates(cert)
			if err != nil {
				return false, fmt.Errorf("failed to encode certificates: %w", err)
			}

			secrets, err := k8sClient.CoreV1().Secrets(m.config.ObjectNamespace).List(ctx, metav1.ListOptions{})
			if err != nil {
				return false, fmt.Errorf("failed to list secrets: %w", err)
			}

			secretName := "aws-tls"
			if common.HasTLSSecret(secrets.Items, secretName) {
				secretName = "secret-init-tls"
			}
			// Create a secret with the CA certificate
			_, err = k8sClient.CoreV1().Secrets(m.config.ObjectNamespace).Create(
				ctx,
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      secretName,
						Namespace: m.config.ObjectNamespace,
					},
					Data: map[string][]byte{
						"ca-bundle.pem": pemBuffer.Bytes(),
					},
				},
				metav1.CreateOptions{},
			)
			if err != nil {
				if apierrors.IsAlreadyExists(err) {
					// If the secret already exists, update it
					existingSecret, err := k8sClient.CoreV1().Secrets(m.config.ObjectNamespace).Get(ctx, secretName, metav1.GetOptions{})
					if err != nil {
						return false, fmt.Errorf("failed to get existing secret: %w", err)
					}

					existingSecret.Data["ca-bundle.pem"] = pemBuffer.Bytes()
					_, err = k8sClient.CoreV1().Secrets(m.config.ObjectNamespace).Update(ctx, existingSecret, metav1.UpdateOptions{})
					if err != nil {
						return false, fmt.Errorf("failed to update secret: %w", err)
					}

				} else {
					return false, fmt.Errorf("failed to create secret: %w", err)
				}
			}

			volumeName := "aws-tls"
			mountPath := "/aws/tls/"
			if common.HasTLSVolume(podSpec.Volumes, volumeName) {
				volumeName = "secret-init-tls"
				mountPath = "/secret-init/tls/"
			}

			container.Env = append(container.Env, corev1.EnvVar{
				Name:  "AWS_CA_BUNDLE",
				Value: mountPath + "ca.bundle.pem",
			})
			container.VolumeMounts = append(container.VolumeMounts, corev1.VolumeMount{
				Name:      volumeName,
				MountPath: mountPath,
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

				return envVars, fmt.Errorf("failed to get data from configmap: %w", err)
			}

			for key, value := range data {
				if isValidPrefix(value) {
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

				return envVars, fmt.Errorf("failed to get data from secret: %w", err)
			}

			for name, v := range data {
				if isValidPrefix(string(v)) {
					envFromSec := corev1.EnvVar{
						Name:  name,
						Value: string(v),
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

			return nil, fmt.Errorf("failed to get data from configmap: %w", err)
		}

		if isValidPrefix(data[env.ValueFrom.ConfigMapKeyRef.Key]) {
			fromCM := corev1.EnvVar{
				Name:  env.Name,
				Value: data[env.ValueFrom.ConfigMapKeyRef.Key],
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

			return nil, fmt.Errorf("failed to get data from secret: %w", err)
		}

		if isValidPrefix(string(data[env.ValueFrom.SecretKeyRef.Key])) {
			fromSecret := corev1.EnvVar{
				Name:  env.Name,
				Value: string(data[env.ValueFrom.SecretKeyRef.Key]),
			}

			return &fromSecret, nil
		}
	}

	return nil, nil
}

func encodeCertificates(cert *acm.GetCertificateOutput) (bytes.Buffer, error) {
	var pemBuffer bytes.Buffer

	// Decode and re-encode the main certificate
	if block, _ := pem.Decode([]byte(aws.StringValue(cert.Certificate))); block != nil {
		err := pem.Encode(&pemBuffer, block)
		if err != nil {
			return pemBuffer, fmt.Errorf("failed to encode main certificate: %w", err)
		}
	} else {
		return pemBuffer, fmt.Errorf("failed to decode main certificate")
	}

	// Decode and re-encode the certificate chain
	chainData := []byte(aws.StringValue(cert.CertificateChain))
	for len(chainData) > 0 {
		var block *pem.Block
		block, chainData = pem.Decode(chainData)
		if block == nil {
			break
		}

		if block.Type == "CERTIFICATE" {
			err := pem.Encode(&pemBuffer, block)
			if err != nil {
				return pemBuffer, fmt.Errorf("failed to encode certificate chain: %w", err)
			}
		}
	}

	return pemBuffer, nil
}

func (m *mutator) addInitContainerForSecretInit(podSecurityContext *corev1.PodSecurityContext, webhookConfig appCommon.Config, secretInitConfig appCommon.SecretInitConfig) []corev1.Container {
	return []corev1.Container{
		{
			Name:            "copy-secret-init",
			Image:           secretInitConfig.Image,
			ImagePullPolicy: secretInitConfig.ImagePullPolicy,
			Command:         []string{"sh", "-c", "cp /usr/local/bin/secret-init /aws/"},
			VolumeMounts: []corev1.VolumeMount{
				{
					Name:      common.SecretInitVolumeName,
					MountPath: "/aws/",
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
		},
	}
}

func (m *mutator) addVolumes(existingVolumes []corev1.Volume) []corev1.Volume {
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

	if m.config.TLSSecretARN != "" {
		m.logger.Debug("TLS secret ARN is set, adding volume for TLS secret ARN")

		volumeName := "aws-tls"
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
								Name: volumeName,
							},
							Items: []corev1.KeyToPath{{
								Key:  "ca-bundle.pem",
								Path: "ca.bundle.pem",
							}},
						},
					}},
				},
			},
		})
	}

	return volumes
}
