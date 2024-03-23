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
	"crypto/x509"
	"log/slog"
	"net/http"

	"emperror.dev/errors"
	"github.com/bank-vaults/vault-sdk/vault"
	vaultapi "github.com/hashicorp/vault/api"
	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/kubernetes"

	"github.com/bank-vaults/secrets-webhook/pkg/common"
	"github.com/bank-vaults/secrets-webhook/pkg/registry"
)

type Vault struct {
	K8sClient kubernetes.Interface
	Namespace string
	Registry  registry.ImageRegistry
	logger    *slog.Logger
	Config    Config
}

func NewProvider(k8sClient kubernetes.Interface, namespace string, registry registry.ImageRegistry, logger *slog.Logger, config Config) *Vault {
	return &Vault{
		K8sClient: k8sClient,
		Namespace: namespace,
		Registry:  registry,
		logger:    logger,
		Config:    config,
	}
}

func (v *Vault) MutatePod(ctx context.Context, pod *corev1.Pod, appConfig common.AppConfig, secretInitConfig common.SecretInitConfig, dryRun bool) error {
	return podMutator(ctx, pod, appConfig, secretInitConfig, v.Config, v.K8sClient, v.Registry, v.logger, dryRun)
}

func (v *Vault) MutateSecret(secret *corev1.Secret) error {
	return secretMutator(secret, v.Config, v.K8sClient, v.Namespace, v.logger)
}

func (v *Vault) MutateConfigMap(configMap *corev1.ConfigMap) error {
	return configMapMutator(configMap, v.Config, v.K8sClient, v.Namespace)
}

func (v *Vault) MutateObject(obj *unstructured.Unstructured) error {
	return objectMutator(obj, v.Config, v.K8sClient, v.Namespace)
}

func NewClient(k8sClient kubernetes.Interface, namespace string, config Config) (*vault.Client, error) {
	clientConfig := vaultapi.DefaultConfig()
	if clientConfig.Error != nil {
		return nil, clientConfig.Error
	}

	clientConfig.Address = config.Addr

	tlsConfig := vaultapi.TLSConfig{Insecure: config.SkipVerify}
	err := clientConfig.ConfigureTLS(&tlsConfig)
	if err != nil {
		return nil, err
	}

	if config.TLSSecret != "" {
		tlsSecret, err := k8sClient.CoreV1().Secrets(namespace).Get(
			context.Background(),
			config.TLSSecret,
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

	if config.VaultServiceAccount != "" {
		sa, err := k8sClient.CoreV1().ServiceAccounts(config.ObjectNamespace).Get(context.Background(), config.VaultServiceAccount, metav1.GetOptions{})
		if err != nil {
			return nil, errors.Wrap(err, "Failed to retrieve specified service account on namespace "+config.ObjectNamespace)
		}

		saToken := ""
		if len(sa.Secrets) > 0 {
			secret, err := k8sClient.CoreV1().Secrets(config.ObjectNamespace).Get(context.Background(), sa.Secrets[0].Name, metav1.GetOptions{})
			if err != nil {
				return nil, errors.Wrap(err, "Failed to retrieve secret for service account "+sa.Secrets[0].Name+" in namespace "+config.ObjectNamespace)
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

			token, err := k8sClient.CoreV1().ServiceAccounts(config.ObjectNamespace).CreateToken(
				context.Background(),
				config.VaultServiceAccount,
				tokenRequest,
				metav1.CreateOptions{},
			)
			if err != nil {
				return nil, errors.Wrap(err, "Failed to create a token for the specified service account "+config.VaultServiceAccount+" on namespace "+config.ObjectNamespace)
			}
			saToken = token.Status.Token
		}

		return vault.NewClientFromConfig(
			clientConfig,
			vault.ClientRole(config.Role),
			vault.ClientAuthPath(config.Path),
			vault.NamespacedSecretAuthMethod,
			vault.ClientLogger(&clientLogger{logger: slog.Default()}),
			vault.ExistingSecret(saToken),
			vault.VaultNamespace(config.VaultNamespace),
		)
	}

	return vault.NewClientFromConfig(
		clientConfig,
		vault.ClientRole(config.Role),
		vault.ClientAuthPath(config.Path),
		vault.ClientAuthMethod(config.AuthMethod),
		vault.ClientLogger(&clientLogger{logger: slog.Default()}),
		vault.VaultNamespace(config.VaultNamespace),
	)
}

func (v *Vault) GetConfig() Config {
	return v.Config
}
