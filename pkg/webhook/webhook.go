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
	"crypto/x509"
	"fmt"
	"log/slog"
	"net/http"
	"os"

	"emperror.dev/errors"
	"github.com/bank-vaults/internal/pkg/baoinjector"
	"github.com/bank-vaults/internal/pkg/vaultinjector"
	"github.com/bank-vaults/vault-sdk/vault"
	bao "github.com/bank-vaults/vault-sdk/vault"
	baoapi "github.com/hashicorp/vault/api"
	vaultapi "github.com/hashicorp/vault/api"
	"github.com/slok/kubewebhook/v2/pkg/log"
	"github.com/slok/kubewebhook/v2/pkg/model"
	"github.com/slok/kubewebhook/v2/pkg/webhook/mutating"
	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/kubernetes"

	"github.com/bank-vaults/secrets-webhook/pkg/common"
	baoprov "github.com/bank-vaults/secrets-webhook/pkg/provider/bao"
	vaultprov "github.com/bank-vaults/secrets-webhook/pkg/provider/vault"
)

// currentlyUsedProvider is the name of the provider
// that is used to mutate the object at the moment.
// This global was introduced to make the code more generic.
// It is mainly used by the hasProviderPrefix and hasInlineProviderDelimiters functions among others.
var currentlyUsedProvider string

type MutatingWebhook struct {
	k8sClient       kubernetes.Interface
	namespace       string
	registry        ImageRegistry
	logger          *slog.Logger
	providerConfigs []interface{}
}

func (mw *MutatingWebhook) SecretsMutator(ctx context.Context, ar *model.AdmissionReview, obj metav1.Object) (*mutating.MutatorResult, error) {
	webhookConfig := common.ParseWebhookConfig(obj)
	secretInitConfig := common.ParseSecretInitConfig(obj)

	if webhookConfig.Mutate || len(webhookConfig.Providers) == 0 {
		return &mutating.MutatorResult{}, nil
	}

	configs, err := parseProviderConfigs(obj, ar, webhookConfig.Providers)
	if err != nil {
		return nil, fmt.Errorf("failed to parse provider configs: %w", err)
	}
	mw.providerConfigs = configs

	switch v := obj.(type) {
	case *corev1.Pod:
		return &mutating.MutatorResult{MutatedObject: v}, mw.MutatePod(ctx, v, webhookConfig, secretInitConfig, ar.DryRun)

	case *corev1.Secret:
		return &mutating.MutatorResult{MutatedObject: v}, mw.MutateSecret(v)

	case *corev1.ConfigMap:
		return &mutating.MutatorResult{MutatedObject: v}, mw.MutateConfigMap(v)

	case *unstructured.Unstructured:
		return &mutating.MutatorResult{MutatedObject: v}, mw.MutateObject(v)

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

func (mw *MutatingWebhook) getDataFromConfigmap(cmName string, ns string) (map[string]string, error) {
	configMap, err := mw.k8sClient.CoreV1().ConfigMaps(ns).Get(context.Background(), cmName, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}

	return configMap.Data, nil
}

func (mw *MutatingWebhook) getDataFromSecret(secretName string, ns string) (map[string][]byte, error) {
	secret, err := mw.k8sClient.CoreV1().Secrets(ns).Get(context.Background(), secretName, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}

	return secret.Data, nil
}

func (mw *MutatingWebhook) lookForEnvFrom(envFrom []corev1.EnvFromSource, ns string) ([]corev1.EnvVar, error) {
	var envVars []corev1.EnvVar

	for _, ef := range envFrom {
		if ef.ConfigMapRef != nil {
			data, err := mw.getDataFromConfigmap(ef.ConfigMapRef.Name, ns)
			if err != nil {
				if apierrors.IsNotFound(err) || (ef.ConfigMapRef.Optional != nil && *ef.ConfigMapRef.Optional) {
					continue
				}

				return envVars, err
			}

			for key, value := range data {
				if hasProviderPrefix(currentlyUsedProvider, value, true) {
					envFromCM := corev1.EnvVar{
						Name:  key,
						Value: value,
					}
					envVars = append(envVars, envFromCM)
				}
			}
		}

		if ef.SecretRef != nil {
			data, err := mw.getDataFromSecret(ef.SecretRef.Name, ns)
			if err != nil {
				if apierrors.IsNotFound(err) || (ef.SecretRef.Optional != nil && *ef.SecretRef.Optional) {
					continue
				}

				return envVars, err
			}

			for name, v := range data {
				value := string(v)
				if hasProviderPrefix(currentlyUsedProvider, value, true) {
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

func (mw *MutatingWebhook) lookForValueFrom(env corev1.EnvVar, ns string) (*corev1.EnvVar, error) {
	if env.ValueFrom.ConfigMapKeyRef != nil {
		data, err := mw.getDataFromConfigmap(env.ValueFrom.ConfigMapKeyRef.Name, ns)
		if err != nil {
			if apierrors.IsNotFound(err) {
				return nil, nil
			}
			return nil, err
		}

		value := data[env.ValueFrom.ConfigMapKeyRef.Key]
		if hasProviderPrefix(currentlyUsedProvider, value, true) {
			fromCM := corev1.EnvVar{
				Name:  env.Name,
				Value: value,
			}
			return &fromCM, nil
		}
	}

	if env.ValueFrom.SecretKeyRef != nil {
		data, err := mw.getDataFromSecret(env.ValueFrom.SecretKeyRef.Name, ns)
		if err != nil {
			if apierrors.IsNotFound(err) {
				return nil, nil
			}
			return nil, err
		}

		value := string(data[env.ValueFrom.SecretKeyRef.Key])
		if hasProviderPrefix(currentlyUsedProvider, value, true) {
			fromSecret := corev1.EnvVar{
				Name:  env.Name,
				Value: value,
			}
			return &fromSecret, nil
		}
	}

	return nil, nil
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
		registry:  NewRegistry(),
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

// parseProviderConfigs parses all provider configs that was declared in the webhook annotation
func parseProviderConfigs(obj metav1.Object, ar *model.AdmissionReview, providers []string) ([]interface{}, error) {
	configs := make([]interface{}, 0, len(providers))
	for _, providerName := range providers {
		switch providerName {
		case vaultprov.ProviderName:
			config, err := vaultprov.ParseConfig(obj, ar)
			if err != nil {
				return nil, errors.Wrap(err, "failed to parse vault config")
			}
			configs = append(configs, config)

		case baoprov.ProviderName:
			config, err := baoprov.ParseConfig(obj, ar)
			if err != nil {
				return nil, errors.Wrap(err, "failed to parse bao config")
			}
			configs = append(configs, config)

		default:
			return nil, errors.Errorf("unknown provider: %s", providerName)
		}
	}

	return configs, nil
}

func hasProviderPrefix(providerName string, value string, withInlineDelimiters bool) bool {
	switch providerName {
	case vaultprov.ProviderName:
		if withInlineDelimiters {
			return common.HasVaultPrefix(value) || vaultinjector.HasInlineVaultDelimiters(value)
		}
		return common.HasVaultPrefix(value)

	case baoprov.ProviderName:
		if withInlineDelimiters {
			return common.HasBaoPrefix(value) || baoinjector.HasInlineBaoDelimiters(value)
		}
		return common.HasBaoPrefix(value)

	default:
		return false
	}
}

func hasInlineProviderDelimiters(providerName, value string) bool {
	switch providerName {
	case vaultprov.ProviderName:
		return vaultinjector.HasInlineVaultDelimiters(value)

	case baoprov.ProviderName:
		return baoinjector.HasInlineBaoDelimiters(value)

	default:
		return false
	}
}

// ======== VAULT ========

func (mw *MutatingWebhook) newVaultClient(vaultConfig vaultprov.Config) (*vault.Client, error) {
	clientConfig := vaultapi.DefaultConfig()
	if clientConfig.Error != nil {
		return nil, clientConfig.Error
	}

	clientConfig.Address = vaultConfig.Addr

	tlsConfig := vaultapi.TLSConfig{Insecure: vaultConfig.SkipVerify}
	err := clientConfig.ConfigureTLS(&tlsConfig)
	if err != nil {
		return nil, err
	}

	if vaultConfig.TLSSecret != "" {
		tlsSecret, err := mw.k8sClient.CoreV1().Secrets(mw.namespace).Get(
			context.Background(),
			vaultConfig.TLSSecret,
			metav1.GetOptions{},
		)
		if err != nil {
			return nil, errors.Wrap(err, "failed to read Vault TLS Secret")
		}

		clientTLSConfig := clientConfig.HttpClient.Transport.(*http.Transport).TLSClientConfig

		pool := x509.NewCertPool()

		ok := pool.AppendCertsFromPEM(tlsSecret.Data["ca.crt"])
		if !ok {
			return nil, errors.Errorf("error loading Vault CA PEM from TLS Secret: %s", tlsSecret.Name)
		}

		clientTLSConfig.RootCAs = pool
	}

	if vaultConfig.VaultServiceAccount != "" {
		sa, err := mw.k8sClient.CoreV1().ServiceAccounts(vaultConfig.ObjectNamespace).Get(context.Background(), vaultConfig.VaultServiceAccount, metav1.GetOptions{})
		if err != nil {
			return nil, errors.Wrap(err, "Failed to retrieve specified service account on namespace "+vaultConfig.ObjectNamespace)
		}

		saToken := ""
		if len(sa.Secrets) > 0 {
			secret, err := mw.k8sClient.CoreV1().Secrets(vaultConfig.ObjectNamespace).Get(context.Background(), sa.Secrets[0].Name, metav1.GetOptions{})
			if err != nil {
				return nil, errors.Wrap(err, "Failed to retrieve secret for service account "+sa.Secrets[0].Name+" in namespace "+vaultConfig.ObjectNamespace)
			}
			saToken = string(secret.Data["token"])
		}

		if saToken == "" {
			tokenTTL := int64(600) // min allowed duration is 10 mins
			tokenRequest := &authenticationv1.TokenRequest{
				Spec: authenticationv1.TokenRequestSpec{
					Audiences:         []string{"https://kubernetes.default.svc"},
					ExpirationSeconds: &tokenTTL,
				},
			}

			token, err := mw.k8sClient.CoreV1().ServiceAccounts(vaultConfig.ObjectNamespace).CreateToken(
				context.Background(),
				vaultConfig.VaultServiceAccount,
				tokenRequest,
				metav1.CreateOptions{},
			)
			if err != nil {
				return nil, errors.Wrap(err, "Failed to create a token for the specified service account "+vaultConfig.VaultServiceAccount+" on namespace "+vaultConfig.ObjectNamespace)
			}
			saToken = token.Status.Token
		}

		return vault.NewClientFromConfig(
			clientConfig,
			vault.ClientRole(vaultConfig.Role),
			vault.ClientAuthPath(vaultConfig.Path),
			vault.NamespacedSecretAuthMethod,
			vault.ClientLogger(&vaultprov.ClientLogger{Logger: mw.logger}),
			vault.ExistingSecret(saToken),
			vault.VaultNamespace(vaultConfig.VaultNamespace),
		)
	}

	return vault.NewClientFromConfig(
		clientConfig,
		vault.ClientRole(vaultConfig.Role),
		vault.ClientAuthPath(vaultConfig.Path),
		vault.ClientAuthMethod(vaultConfig.AuthMethod),
		vault.ClientLogger(&vaultprov.ClientLogger{Logger: mw.logger}),
		vault.VaultNamespace(vaultConfig.VaultNamespace),
	)
}

// ======== BAO ========

func (mw *MutatingWebhook) newBaoClient(baoConfig baoprov.Config) (*bao.Client, error) {
	clientConfig := baoapi.DefaultConfig()
	if clientConfig.Error != nil {
		return nil, clientConfig.Error
	}

	clientConfig.Address = baoConfig.Addr

	tlsConfig := baoapi.TLSConfig{Insecure: baoConfig.SkipVerify}
	err := clientConfig.ConfigureTLS(&tlsConfig)
	if err != nil {
		return nil, err
	}

	if baoConfig.TLSSecret != "" {
		tlsSecret, err := mw.k8sClient.CoreV1().Secrets(mw.namespace).Get(
			context.Background(),
			baoConfig.TLSSecret,
			metav1.GetOptions{},
		)
		if err != nil {
			return nil, errors.Wrap(err, "failed to read Bao TLS Secret")
		}

		clientTLSConfig := clientConfig.HttpClient.Transport.(*http.Transport).TLSClientConfig

		pool := x509.NewCertPool()

		ok := pool.AppendCertsFromPEM(tlsSecret.Data["ca.crt"])
		if !ok {
			return nil, errors.Errorf("error loading Bao CA PEM from TLS Secret: %s", tlsSecret.Name)
		}

		clientTLSConfig.RootCAs = pool
	}

	if baoConfig.BaoServiceAccount != "" {
		sa, err := mw.k8sClient.CoreV1().ServiceAccounts(baoConfig.ObjectNamespace).Get(context.Background(), baoConfig.BaoServiceAccount, metav1.GetOptions{})
		if err != nil {
			return nil, errors.Wrap(err, "Failed to retrieve specified service account on namespace "+baoConfig.ObjectNamespace)
		}

		saToken := ""
		if len(sa.Secrets) > 0 {
			secret, err := mw.k8sClient.CoreV1().Secrets(baoConfig.ObjectNamespace).Get(context.Background(), sa.Secrets[0].Name, metav1.GetOptions{})
			if err != nil {
				return nil, errors.Wrap(err, "Failed to retrieve secret for service account "+sa.Secrets[0].Name+" in namespace "+baoConfig.ObjectNamespace)
			}
			saToken = string(secret.Data["token"])
		}

		if saToken == "" {
			tokenTTL := int64(600) // min allowed duration is 10 mins
			tokenRequest := &authenticationv1.TokenRequest{
				Spec: authenticationv1.TokenRequestSpec{
					Audiences:         []string{"https://kubernetes.default.svc"},
					ExpirationSeconds: &tokenTTL,
				},
			}

			token, err := mw.k8sClient.CoreV1().ServiceAccounts(baoConfig.ObjectNamespace).CreateToken(
				context.Background(),
				baoConfig.BaoServiceAccount,
				tokenRequest,
				metav1.CreateOptions{},
			)
			if err != nil {
				return nil, errors.Wrap(err, "Failed to create a token for the specified service account "+baoConfig.BaoServiceAccount+" on namespace "+baoConfig.ObjectNamespace)
			}
			saToken = token.Status.Token
		}

		return bao.NewClientFromConfig(
			clientConfig,
			bao.ClientRole(baoConfig.Role),
			bao.ClientAuthPath(baoConfig.Path),
			bao.NamespacedSecretAuthMethod,
			bao.ClientLogger(&baoprov.ClientLogger{Logger: mw.logger}),
			bao.ExistingSecret(saToken),
			bao.VaultNamespace(baoConfig.BaoNamespace),
		)
	}

	return bao.NewClientFromConfig(
		clientConfig,
		bao.ClientRole(baoConfig.Role),
		bao.ClientAuthPath(baoConfig.Path),
		bao.ClientAuthMethod(baoConfig.AuthMethod),
		bao.ClientLogger(&baoprov.ClientLogger{Logger: mw.logger}),
		bao.VaultNamespace(baoConfig.BaoNamespace),
	)
}
