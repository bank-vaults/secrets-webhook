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

package provider

import (
	"context"
	"log/slog"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/kubernetes"

	appCommon "github.com/bank-vaults/secrets-webhook/pkg/common"
	"github.com/bank-vaults/secrets-webhook/pkg/registry"
)

type Mutator interface {
	MutateConfigMap(configMap *corev1.ConfigMap) error
	MutateSecret(secret *corev1.Secret) error
	MutateObject(object *unstructured.Unstructured) error
	MutatePod(ctx context.Context, pod *corev1.Pod, webhookConfig appCommon.Config, secretInitConfig appCommon.SecretInitConfig, k8sClient kubernetes.Interface, registry registry.ImageRegistry, dryRun bool) error
	// For testing purposes
	MutateContainers(ctx context.Context, containers []corev1.Container, podSpec *corev1.PodSpec, webhookConfig appCommon.Config, secretInitConfig appCommon.SecretInitConfig, k8sClient kubernetes.Interface, registry registry.ImageRegistry) (bool, error)
}

type Provider interface {
	NewMutator(ctx context.Context, obj metav1.Object, client kubernetes.Interface, arNamespace string, k8sNamespace string, logger *slog.Logger) (*Mutator, error)
}
