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

	vaultinjector "github.com/bank-vaults/vault-sdk/injector/vault"
	corev1 "k8s.io/api/core/v1"

	"github.com/bank-vaults/secrets-webhook/pkg/provider"
	"github.com/bank-vaults/secrets-webhook/pkg/provider/common"
)

func (m *mutator) MutateConfigMap(ctx context.Context, mutateRequest provider.ConfigMapMutateRequest) error {
	// do an early exit if no mutation is needed
	if !configMapNeedsMutation(mutateRequest.ConfigMap) {
		return nil
	}

	err := m.newClient(ctx, mutateRequest.K8sClient, mutateRequest.K8sNamespace)
	if err != nil {
		return err
	}
	defer m.client.Close()

	injector := vaultinjector.NewSecretInjector(
		vaultinjector.Config{
			TransitKeyID:     m.config.TransitKeyID,
			TransitPath:      m.config.TransitPath,
			TransitBatchSize: m.config.TransitBatchSize,
		}, m.client, nil /* vaultinjector.SecretRenewer */, m.logger)

	mutateRequest.ConfigMap.Data, err = injector.GetDataFromVaultWithContext(ctx, mutateRequest.ConfigMap.Data)
	if err != nil {
		return err
	}

	for key, value := range mutateRequest.ConfigMap.BinaryData {
		if isValidPrefix(string(value)) {
			mapData, err := injector.GetDataFromVaultWithContext(ctx, map[string]string{
				key: string(value),
			})
			if err != nil {
				return err
			}

			err = common.MutateConfigMapBinaryData(mutateRequest.ConfigMap, mapData)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func configMapNeedsMutation(configMap *corev1.ConfigMap) bool {
	for _, value := range configMap.Data {
		if isValidPrefix(value) {
			return true
		}
	}

	for _, value := range configMap.BinaryData {
		if isValidPrefix(string(value)) {
			return true
		}
	}

	return false
}
