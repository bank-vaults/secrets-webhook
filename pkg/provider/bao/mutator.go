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
	"crypto/x509"
	"log/slog"
	"net/http"

	"emperror.dev/errors"
	bao "github.com/bank-vaults/vault-sdk/vault"
	baoapi "github.com/hashicorp/vault/api"
	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

type mutator struct {
	client *bao.Client
	config *Config
	logger *slog.Logger
}

func (m *mutator) newClient(ctx context.Context, k8sClient kubernetes.Interface, k8sNamespace string) error {
	clientConfig := baoapi.DefaultConfig()
	if clientConfig.Error != nil {
		return clientConfig.Error
	}
	clientConfig.Address = m.config.Addr

	err := clientConfig.ConfigureTLS(&baoapi.TLSConfig{Insecure: m.config.SkipVerify})
	if err != nil {
		return err
	}

	if m.config.TLSSecret != "" {
		tlsSecret, err := k8sClient.CoreV1().Secrets(k8sNamespace).Get(
			ctx,
			m.config.TLSSecret,
			metav1.GetOptions{},
		)
		if err != nil {
			return errors.Wrap(err, "failed to read Bao TLS Secret")
		}

		pool := x509.NewCertPool()
		ok := pool.AppendCertsFromPEM(tlsSecret.Data["ca.crt"])
		if !ok {
			return errors.Errorf("error loading Bao CA PEM from TLS Secret: %s", tlsSecret.Name)
		}
		clientConfig.HttpClient.Transport.(*http.Transport).TLSClientConfig.RootCAs = pool
	}

	if m.config.BaoServiceAccount != "" {
		sa, err := k8sClient.CoreV1().ServiceAccounts(m.config.ObjectNamespace).Get(ctx, m.config.BaoServiceAccount, metav1.GetOptions{})
		if err != nil {
			return errors.Wrap(err, "Failed to retrieve specified service account on namespace "+m.config.ObjectNamespace)
		}

		saToken := ""
		if len(sa.Secrets) > 0 {
			secret, err := k8sClient.CoreV1().Secrets(m.config.ObjectNamespace).Get(ctx, sa.Secrets[0].Name, metav1.GetOptions{})
			if err != nil {
				return errors.Wrap(err, "Failed to retrieve secret for service account "+sa.Secrets[0].Name+" in namespace "+m.config.ObjectNamespace)
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

			token, err := k8sClient.CoreV1().ServiceAccounts(m.config.ObjectNamespace).CreateToken(
				ctx,
				m.config.BaoServiceAccount,
				tokenRequest,
				metav1.CreateOptions{},
			)
			if err != nil {
				return errors.Wrap(err, "Failed to create a token for the specified service account "+m.config.BaoServiceAccount+" on namespace "+m.config.ObjectNamespace)
			}

			saToken = token.Status.Token
		}

		baoClient, err := bao.NewClientFromConfig(
			clientConfig,
			bao.ClientRole(m.config.Role),
			bao.ClientAuthPath(m.config.Path),
			bao.NamespacedSecretAuthMethod,
			bao.ClientLogger(&ClientLogger{Logger: m.logger}),
			bao.ExistingSecret(saToken),
			bao.VaultNamespace(m.config.BaoNamespace),
		)
		if err != nil {
			return errors.Wrap(err, "failed to create Bao client")
		}

		m.client = baoClient

		return nil
	}

	baoClient, err := bao.NewClientFromConfig(
		clientConfig,
		bao.ClientRole(m.config.Role),
		bao.ClientAuthPath(m.config.Path),
		bao.ClientAuthMethod(m.config.AuthMethod),
		bao.ClientLogger(&ClientLogger{Logger: m.logger}),
		bao.VaultNamespace(m.config.BaoNamespace),
	)
	if err != nil {
		return errors.Wrap(err, "failed to create Bao client")
	}
	m.client = baoClient

	return nil
}
