package vault

import (
	"encoding/base64"
	"log/slog"

	"emperror.dev/errors"
	"github.com/bank-vaults/internal/injector"
	"github.com/bank-vaults/secrets-webhook/pkg/common"
	"github.com/bank-vaults/vault-sdk/vault"
	corev1 "k8s.io/api/core/v1"
)

func configMapMutator(configMap *corev1.ConfigMap, config Config, client *vault.Client) error {
	// do an early exit and don't construct the Vault client if not needed
	if !configMapNeedsMutation(configMap) {
		return nil
	}

	defer client.Close()

	injectorConfig := injector.Config{
		TransitKeyID:     config.TransitKeyID,
		TransitPath:      config.TransitPath,
		TransitBatchSize: config.TransitBatchSize,
	}

	secretInjector := injector.NewSecretInjector(injectorConfig, client, nil, slog.Default())

	var err error
	configMap.Data, err = secretInjector.GetDataFromVault(configMap.Data)
	if err != nil {
		return err
	}

	for key, value := range configMap.BinaryData {
		if common.HasVaultPrefix(string(value)) {
			binaryData := map[string]string{
				key: string(value),
			}
			err := mutateConfigMapBinaryData(configMap, binaryData, &secretInjector)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func configMapNeedsMutation(configMap *corev1.ConfigMap) bool {
	for _, value := range configMap.Data {
		if common.HasVaultPrefix(value) || injector.HasInlineVaultDelimiters(value) {
			return true
		}
	}
	for _, value := range configMap.BinaryData {
		if common.HasVaultPrefix(string(value)) {
			return true
		}
	}

	return false
}

func mutateConfigMapBinaryData(configMap *corev1.ConfigMap, data map[string]string, secretInjector *injector.SecretInjector) error {
	mapData, err := secretInjector.GetDataFromVault(data)
	if err != nil {
		return err
	}

	for key, value := range mapData {
		// binary data are stored in base64 inside vault
		// we need to decode base64 since k8s will encode this data too
		valueBytes, err := base64.StdEncoding.DecodeString(value)
		if err != nil {
			return errors.Wrapf(err, "failed to decode ConfigMap binary data")
		}
		configMap.BinaryData[key] = valueBytes
	}

	return nil
}
