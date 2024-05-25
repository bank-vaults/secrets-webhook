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

//go:build integration
// +build integration

package vault

import (
	"context"
	"log/slog"
	"testing"

	"github.com/bank-vaults/vault-sdk/vault"
	vaultapi "github.com/hashicorp/vault/api"
	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
	kubernetesConfig "sigs.k8s.io/controller-runtime/pkg/client/config"
)

func TestMutateConfigMap(t *testing.T) {
	config := vaultapi.DefaultConfig()
	if config.Error != nil {
		assert.NoError(t, config.Error)
	}
	config.Address = "http://localhost:8200"

	client, err := vault.NewClientFromConfig(config)
	assert.NoError(t, err)

	_, err = client.RawClient().Logical().Write("secret/data/account", vault.NewData(0, map[string]interface{}{"access_key": "superusername", "secret_key": "secret"}))
	assert.NoError(t, err)

	t.Cleanup(func() {
		_, err = client.RawClient().Logical().Delete("secret/metadata/account")
		assert.NoError(t, err)
	})

	configMap := corev1.ConfigMap{
		Data: map[string]string{
			"aws-access-key-id": "vault:secret/data/account#access_key",
			"appsettings-inline": `{
				"Credentials": {
					"ACCESS_KEY": "${vault:secret/data/account#access_key}",
					"SECRET_KEY": "${vault:secret/data/account#secret_key}"
				}
			}`,
		},
	}
	kubeConfig, err := kubernetesConfig.GetConfig()
	assert.NoError(t, err)

	k8sClient, err := kubernetes.NewForConfig(kubeConfig)
	assert.NoError(t, err)

	mutator := mutator{client: client, config: &Config{}, logger: slog.Default()}
	err = mutator.MutateConfigMap(context.Background(), &configMap, k8sClient, "default")

	assert.NoError(t, err)

	assert.Equal(t, map[string]string{
		"aws-access-key-id": "superusername",
		"appsettings-inline": `{
				"Credentials": {
					"ACCESS_KEY": "superusername",
					"SECRET_KEY": "secret"
				}
			}`,
	}, configMap.Data)
}
