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
	"encoding/base64"

	"emperror.dev/errors"
	"github.com/bank-vaults/internal/pkg/baoinjector"
	"github.com/bank-vaults/internal/pkg/vaultinjector"
	corev1 "k8s.io/api/core/v1"

	"github.com/bank-vaults/secrets-webhook/pkg/common"
	"github.com/bank-vaults/secrets-webhook/pkg/provider/bao"
	"github.com/bank-vaults/secrets-webhook/pkg/provider/vault"
)

func (mw *MutatingWebhook) MutateConfigMap(configMap *corev1.ConfigMap, configs []interface{}) error {
	// do an early exit if no mutation is needed
	if !configMapNeedsMutation(configMap) {
		return nil
	}

	for _, config := range configs {
		switch providerConfig := config.(type) {
		case vault.Config:
			currentlyUsedProvider = vault.ProviderName

			err := mw.mutateConfigMapForVault(configMap, providerConfig)
			if err != nil {
				return errors.Wrap(err, "failed to mutate secret")
			}

		case bao.Config:
			currentlyUsedProvider = bao.ProviderName

			err := mw.mutateConfigMapForBao(configMap, providerConfig)
			if err != nil {
				return errors.Wrap(err, "failed to mutate secret")
			}

		default:
			return errors.Errorf("unknown provider config type: %T", config)
		}
	}

	return nil
}

func configMapNeedsMutation(configMap *corev1.ConfigMap) bool {
	for _, value := range configMap.Data {
		if hasProviderPrefix(currentlyUsedProvider, value, true) {
			return true
		}
	}
	for _, value := range configMap.BinaryData {
		if hasProviderPrefix(currentlyUsedProvider, string(value), false) {
			return true
		}
	}

	return false
}

func (mw *MutatingWebhook) mutateConfigMapBinaryData(configMap *corev1.ConfigMap, mapData map[string]string) error {
	for key, value := range mapData {
		// NOTE: If the binary data is stored in base64 by the provider,
		// we need to base64 decode it since Kubernetes will encode this data too.

		// Check if the value is base64 encoded by trying to decode it
		valueBytes, err := base64.StdEncoding.DecodeString(value)
		if err != nil {
			// If the value is not base64 encoded, use the value as is
			configMap.Data[key] = value
		} else {
			// If the value is base64 encoded, use the decoded value
			configMap.BinaryData[key] = valueBytes
		}
	}

	return nil
}

// ======== VAULT ========

func (mw *MutatingWebhook) mutateConfigMapForVault(configMap *corev1.ConfigMap, vaultConfig vault.Config) error {
	vaultClient, err := mw.newVaultClient(vaultConfig)
	if err != nil {
		return errors.Wrap(err, "failed to create vault client")
	}
	defer vaultClient.Close()

	config := vaultinjector.Config{
		TransitKeyID:     vaultConfig.TransitKeyID,
		TransitPath:      vaultConfig.TransitPath,
		TransitBatchSize: vaultConfig.TransitBatchSize,
	}
	secretInjector := vaultinjector.NewSecretInjector(config, vaultClient, nil, logger)

	configMap.Data, err = secretInjector.GetDataFromVault(configMap.Data)
	if err != nil {
		return err
	}

	for key, value := range configMap.BinaryData {
		if common.HasVaultPrefix(string(value)) {
			binaryData := map[string]string{
				key: string(value),
			}

			mapData, err := secretInjector.GetDataFromVault(binaryData)
			if err != nil {
				return err
			}

			err = mw.mutateConfigMapBinaryData(configMap, mapData)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

// ======== BAO ========

func (mw *MutatingWebhook) mutateConfigMapForBao(configMap *corev1.ConfigMap, baoConfig bao.Config) error {
	baoClient, err := mw.newBaoClient(baoConfig)
	if err != nil {
		return errors.Wrap(err, "failed to create bao client")
	}
	defer baoClient.Close()

	config := baoinjector.Config{
		TransitKeyID:     baoConfig.TransitKeyID,
		TransitPath:      baoConfig.TransitPath,
		TransitBatchSize: baoConfig.TransitBatchSize,
	}
	injector := baoinjector.NewSecretInjector(config, baoClient, nil, logger)

	configMap.Data, err = injector.GetDataFromBao(configMap.Data)
	if err != nil {
		return err
	}

	for key, value := range configMap.BinaryData {
		if common.HasBaoPrefix(string(value)) {
			binaryData := map[string]string{
				key: string(value),
			}

			mapData, err := injector.GetDataFromBao(binaryData)
			if err != nil {
				return err
			}

			err = mw.mutateConfigMapBinaryData(configMap, mapData)
			if err != nil {
				return err
			}
		}
	}

	return nil
}
