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
	"context"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	appCommon "github.com/bank-vaults/secrets-webhook/pkg/common"
)

const SecretInitVolumeName = "secret-init"

func IsPodAlreadyMutated(pod *corev1.Pod) bool {
	for _, volume := range pod.Spec.Volumes {
		if volume.Name == SecretInitVolumeName {
			return true
		}
	}

	return false
}

// If the original Pod contained a Volume "{providerName}-tls", for example Vault instances provisioned by the Operator
// we need to handle that edge case and choose another name for the vault-tls volume for accessing Vault with TLS.
func HasTLSVolume(volumes []corev1.Volume, tlsVolumeName string) bool {
	for _, volume := range volumes {
		if volume.Name == tlsVolumeName {
			return true
		}
	}

	return false
}

// isLogLevelSet checks if the SECRET_INIT_LOG_LEVEL environment variable
// has already been set in the container, so it doesn't get overridden.
func IsLogLevelSet(envVars []corev1.EnvVar) bool {
	for _, envVar := range envVars {
		if envVar.Name == "SECRET_INIT_LOG_LEVEL" {
			return true
		}
	}

	return false
}

func GetDataFromConfigmap(ctx context.Context, k8sClient kubernetes.Interface, cmName string, ns string) (map[string]string, error) {
	configMap, err := k8sClient.CoreV1().ConfigMaps(ns).Get(ctx, cmName, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}

	return configMap.Data, nil
}

func GetDataFromSecret(ctx context.Context, k8sClient kubernetes.Interface, secretName string, ns string) (map[string][]byte, error) {
	secret, err := k8sClient.CoreV1().Secrets(ns).Get(ctx, secretName, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}

	return secret.Data, nil
}

func GetBaseSecurityContext(podSecurityContext *corev1.PodSecurityContext, webhookConfig appCommon.Config) *corev1.SecurityContext {
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

func GetServiceAccountMount(containers []corev1.Container, serviceAccountTokenVolumeName string) (serviceAccountMount corev1.VolumeMount) {
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
