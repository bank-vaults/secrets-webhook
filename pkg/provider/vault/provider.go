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

package vault

import (
	"context"
	"crypto/x509"
	"log/slog"
	"net/http"
	"strings"

	"emperror.dev/errors"
	"github.com/bank-vaults/vault-sdk/vault"
	vaultapi "github.com/hashicorp/vault/api"
	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/bank-vaults/secrets-webhook/pkg/provider"
)

const (
	AgentConfig = `
	pid_file = "/tmp/pidfile"
	
	auto_auth {
			method "kubernetes" {
					namespace = "%s"
					mount_path = "auth/%s"
					config = {
							role = "%s"
					}
			}
	
			sink "file" {
					config = {
							path = "/vault/.vault-token"
					}
			}
	}`

	ProviderName = "vault"
)

type Provider struct{}

func (*Provider) NewMutator(_ context.Context, obj metav1.Object, client kubernetes.Interface, arNamespace string, k8sNamespace string, logger *slog.Logger) (provider.Mutator, error) {
	config, err := LoadConfig(obj, arNamespace)
	if err != nil {
		return nil, errors.Wrap(err, "failed to load Vault configuration")
	}

	clientConfig := vaultapi.DefaultConfig()
	if clientConfig.Error != nil {
		return nil, clientConfig.Error
	}

	clientConfig.Address = config.Addr

	tlsConfig := vaultapi.TLSConfig{Insecure: config.SkipVerify}
	err = clientConfig.ConfigureTLS(&tlsConfig)
	if err != nil {
		return nil, err
	}

	if config.TLSSecret != "" {
		tlsSecret, err := client.CoreV1().Secrets(k8sNamespace).Get(
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
		sa, err := client.CoreV1().ServiceAccounts(config.ObjectNamespace).Get(context.Background(), config.VaultServiceAccount, metav1.GetOptions{})
		if err != nil {
			return nil, errors.Wrap(err, "Failed to retrieve specified service account on namespace "+config.ObjectNamespace)
		}

		saToken := ""
		if len(sa.Secrets) > 0 {
			secret, err := client.CoreV1().Secrets(config.ObjectNamespace).Get(context.Background(), sa.Secrets[0].Name, metav1.GetOptions{})
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

			token, err := client.CoreV1().ServiceAccounts(config.ObjectNamespace).CreateToken(
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

		vaultClient, err := vault.NewClientFromConfig(
			clientConfig,
			vault.ClientRole(config.Role),
			vault.ClientAuthPath(config.Path),
			vault.NamespacedSecretAuthMethod,
			vault.ClientLogger(&ClientLogger{Logger: logger}),
			vault.ExistingSecret(saToken),
			vault.VaultNamespace(config.VaultNamespace),
		)
		if err != nil {
			return nil, errors.Wrap(err, "failed to create Vault client")
		}

		return &mutator{client: vaultClient, config: &config, logger: logger}, nil
	}

	vaultClient, err := vault.NewClientFromConfig(
		clientConfig,
		vault.ClientRole(config.Role),
		vault.ClientAuthPath(config.Path),
		vault.ClientAuthMethod(config.AuthMethod),
		vault.ClientLogger(&ClientLogger{Logger: logger}),
		vault.VaultNamespace(config.VaultNamespace),
	)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create Vault client")
	}

	return &mutator{client: vaultClient, config: &config, logger: logger}, nil
}

func isValidPrefix(value string) bool {
	return strings.HasPrefix(value, "vault:") || strings.HasPrefix(value, ">>vault:")
}
