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

// Mutator is the interface that must be implemented by a mutator
type Mutator interface {
	MutateConfigMap(ctx context.Context, configMapMutateRequest ConfigMapMutateRequest) error
	MutateSecret(ctx context.Context, secretMutateRequest SecretMutateRequest) error
	MutateObject(ctx context.Context, objectMutateRequest ObjectMutateRequest) error
	MutatePod(ctx context.Context, podMutateRequest PodMutateRequest) error
	// For testing purposes
	MutateContainers(ctx context.Context, containers []corev1.Container, podSpec *corev1.PodSpec, webhookConfig appCommon.Config, secretInitConfig appCommon.SecretInitConfig, k8sClient kubernetes.Interface, registry registry.ImageRegistry) (bool, error)
}

// ConfigMapMutateRequest is the request object for mutating a ConfigMap
type ConfigMapMutateRequest struct {
	ConfigMap    *corev1.ConfigMap
	K8sClient    kubernetes.Interface
	K8sNamespace string
}

// SecretMutateRequest is the request object for mutating a Secret
type SecretMutateRequest struct {
	Secret       *corev1.Secret
	K8sClient    kubernetes.Interface
	K8sNamespace string
}

// ObjectMutateRequest is the request object for mutating an Object
type ObjectMutateRequest struct {
	Object       *unstructured.Unstructured
	K8sClient    kubernetes.Interface
	K8sNamespace string
}

// PodMutateRequest is the request object for mutating a Pod
type PodMutateRequest struct {
	Pod              *corev1.Pod
	WebhookConfig    appCommon.Config
	SecretInitConfig appCommon.SecretInitConfig
	K8sClient        kubernetes.Interface
	Registry         registry.ImageRegistry
	DryRun           bool
}

// Provider is the interface that must be implemented by a provider
type Provider interface {
	NewMutator(obj metav1.Object, arNamespace string, logger *slog.Logger) (*Mutator, error)
}
