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
	"fmt"
	"log/slog"
	"net/http"
	"os"

	"emperror.dev/errors"
	"github.com/slok/kubewebhook/v2/pkg/log"
	"github.com/slok/kubewebhook/v2/pkg/model"
	"github.com/slok/kubewebhook/v2/pkg/webhook/mutating"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/kubernetes"

	"github.com/bank-vaults/secrets-webhook/pkg/common"
	"github.com/bank-vaults/secrets-webhook/pkg/provider"
	baoprov "github.com/bank-vaults/secrets-webhook/pkg/provider/bao"
	vaultprov "github.com/bank-vaults/secrets-webhook/pkg/provider/vault"
	"github.com/bank-vaults/secrets-webhook/pkg/registry"
)

type MutatingWebhook struct {
	k8sClient kubernetes.Interface
	namespace string
	registry  registry.ImageRegistry
	logger    *slog.Logger
}

func (mw *MutatingWebhook) SecretsMutator(ctx context.Context, ar *model.AdmissionReview, obj metav1.Object) (*mutating.MutatorResult, error) {
	webhookConfig := common.LoadWebhookConfig(obj)
	secretInitConfig := common.LoadSecretInitConfig(obj)

	if webhookConfig.Mutate || webhookConfig.Provider == "" {
		return &mutating.MutatorResult{}, nil
	}

	var mutator provider.Mutator
	var err error
	switch webhookConfig.Provider {
	case vaultprov.ProviderName:
		provider := vaultprov.Provider{}
		mutator, err = provider.NewMutator(obj, ar.Namespace, mw.logger)
		if err != nil {
			return &mutating.MutatorResult{}, errors.Wrap(err, "failed to create Vault mutator")
		}

	case baoprov.ProviderName:
		provider := baoprov.Provider{}
		mutator, err = provider.NewMutator(obj, ar.Namespace, mw.logger)
		if err != nil {
			return &mutating.MutatorResult{}, errors.Wrap(err, "failed to create Bao mutator")
		}

	default:
		return &mutating.MutatorResult{}, nil
	}

	switch v := obj.(type) {
	case *corev1.Pod:
		return &mutating.MutatorResult{MutatedObject: v}, mutator.MutatePod(ctx, v, webhookConfig, secretInitConfig, mw.k8sClient, mw.registry, ar.DryRun)

	case *corev1.Secret:
		return &mutating.MutatorResult{MutatedObject: v}, mutator.MutateSecret(ctx, v, mw.k8sClient, mw.namespace)

	case *corev1.ConfigMap:
		return &mutating.MutatorResult{MutatedObject: v}, mutator.MutateConfigMap(ctx, v, mw.k8sClient, mw.namespace)

	case *unstructured.Unstructured:
		return &mutating.MutatorResult{MutatedObject: v}, mutator.MutateObject(ctx, v, mw.k8sClient, mw.namespace)

	default:
		return &mutating.MutatorResult{}, nil
	}
}

func (mw *MutatingWebhook) ServeMetrics(addr string, handler http.Handler) {
	mw.logger.Info(fmt.Sprintf("Telemetry on http://%s", addr))

	mux := http.NewServeMux()
	mux.Handle("/metrics", handler)

	err := http.ListenAndServe(addr, mux)
	if err != nil {
		mw.logger.Error(fmt.Errorf("error serving telemetry: %w", err).Error())
		os.Exit(1)
	}
}

func NewMutatingWebhook(logger *slog.Logger, k8sClient kubernetes.Interface) (*MutatingWebhook, error) {
	namespace := os.Getenv("KUBERNETES_NAMESPACE") // only for kurun
	if namespace == "" {
		namespaceBytes, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/namespace")
		if err != nil {
			return nil, errors.Wrap(err, "error reading k8s namespace")
		}
		namespace = string(namespaceBytes)
	}

	return &MutatingWebhook{
		k8sClient: k8sClient,
		namespace: namespace,
		registry:  registry.NewRegistry(),
		logger:    logger,
	}, nil
}

func ErrorLoggerMutator(mutator mutating.MutatorFunc, logger log.Logger) mutating.MutatorFunc {
	return func(ctx context.Context, ar *model.AdmissionReview, obj metav1.Object) (result *mutating.MutatorResult, err error) {
		r, err := mutator(ctx, ar, obj)
		if err != nil {
			logger.WithCtxValues(ctx).WithValues(log.Kv{
				"error": err,
			}).Errorf("Admission review request failed")
		}
		return r, err
	}
}
