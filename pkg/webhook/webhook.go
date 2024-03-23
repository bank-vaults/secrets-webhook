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
	"k8s.io/client-go/kubernetes"

	"github.com/bank-vaults/secrets-webhook/pkg/common"
	"github.com/bank-vaults/secrets-webhook/pkg/provider"
	"github.com/bank-vaults/secrets-webhook/pkg/provider/vault"
	"github.com/bank-vaults/secrets-webhook/pkg/registry"
)

type MutatingWebhook struct {
	K8sClient kubernetes.Interface
	Namespace string
	Registry  registry.ImageRegistry
	Logger    *slog.Logger
}

func (mw *MutatingWebhook) SecretsMutator(ctx context.Context, ar *model.AdmissionReview, obj metav1.Object) (*mutating.MutatorResult, error) {
	appConfig := common.ParseAppConfig(obj)
	// secretInitConfig := common.ParseSecretInitConfig(obj)

	// If vault.security.banzaicloud.io/mutate is false, return immediately
	if !appConfig.Mutate {
		return &mutating.MutatorResult{}, nil
	}

	providers, err := getSecretProviders(appConfig.Providers, mw, obj, ar)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get secret providers")
	}

	switch v := obj.(type) {
	// case *corev1.Pod:
	// 	return &mutating.MutatorResult{MutatedObject: v}, provider.MutatePod(ctx, v, appConfig, secretInitConfig, ar.DryRun)

	case *corev1.Secret:
		return &mutating.MutatorResult{MutatedObject: v}, mw.MutateSecret(v, providers)

	// case *corev1.ConfigMap:
	// 	return &mutating.MutatorResult{MutatedObject: v}, provider.MutateConfigMap(v)

	// case *unstructured.Unstructured:
	// 	return &mutating.MutatorResult{MutatedObject: v}, provider.MutateObject(v)

	default:
		return &mutating.MutatorResult{}, nil
	}
}

func (mw *MutatingWebhook) ServeMetrics(addr string, handler http.Handler) {
	mw.Logger.Info(fmt.Sprintf("Telemetry on http://%s", addr))

	mux := http.NewServeMux()
	mux.Handle("/metrics", handler)
	err := http.ListenAndServe(addr, mux)
	if err != nil {
		mw.Logger.Error(fmt.Errorf("error serving telemetry: %w", err).Error())
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
		K8sClient: k8sClient,
		Namespace: namespace,
		Registry:  registry.NewRegistry(),
		Logger:    logger,
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

func getSecretProviders(providers []string, mw *MutatingWebhook, obj metav1.Object, ar *model.AdmissionReview) (map[string]provider.Provider, error) {
	providerMap := make(map[string]provider.Provider)

	for _, providerName := range providers {
		switch providerName {
		case "vault":
			vaultConfig, err := vault.ParseConfig(obj, ar)
			if err != nil {
				return nil, errors.Wrap(err, "failed to parse vault config")
			}
			provider := vault.NewProvider(mw.K8sClient, mw.Namespace, mw.Registry, mw.Logger, vaultConfig)

			providerMap[providerName] = provider

		default:
			return nil, errors.Errorf("provider %s not supported", providerName)
		}
	}

	return providerMap, nil
}
