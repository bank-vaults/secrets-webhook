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

	"github.com/bank-vaults/internal/pkg/vaultinjector"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/bank-vaults/secrets-webhook/pkg/provider/common"
)

func (m *mutator) MutateConfigMap(ctx context.Context, configMap *corev1.ConfigMap, k8sClient kubernetes.Interface, k8sNamespace string) error {
	// do an early exit if no mutation is needed
	if !configMapNeedsMutation(configMap) {
		return nil
	}

	err := m.newClient(ctx, k8sClient, k8sNamespace)
	if err != nil {
		return err
	}
	defer m.client.Close()

	config := vaultinjector.Config{
		TransitKeyID:     m.config.TransitKeyID,
		TransitPath:      m.config.TransitPath,
		TransitBatchSize: m.config.TransitBatchSize,
	}
	injector := vaultinjector.NewSecretInjector(config, m.client, nil, m.logger)

	configMap.Data, err = injector.GetDataFromVault(configMap.Data)
	if err != nil {
		return err
	}

	for key, value := range configMap.BinaryData {
		if isValidPrefix(string(value)) {
			binaryData := map[string]string{
				key: string(value),
			}

			mapData, err := injector.GetDataFromVault(binaryData)
			if err != nil {
				return err
			}

			err = common.MutateConfigMapBinaryData(configMap, mapData)
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
