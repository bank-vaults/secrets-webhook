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
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"emperror.dev/errors"
	vaultinjector "github.com/bank-vaults/internal/pkg/injector/vault"
	corev1 "k8s.io/api/core/v1"

	"github.com/bank-vaults/secrets-webhook/pkg/provider"
	"github.com/bank-vaults/secrets-webhook/pkg/provider/common"
)

func (m *mutator) MutateSecret(ctx context.Context, mutateRequest provider.SecretMutateRequest) error {
	// do an early exit if no mutation is needed
	requiredToMutate, err := secretNeedsMutation(mutateRequest.Secret)
	if err != nil {
		return errors.Wrap(err, "failed to check if secret needs to be mutated")
	}

	if !requiredToMutate {
		return nil
	}

	err = m.newClient(ctx, mutateRequest.K8sClient, mutateRequest.K8sNamespace)
	if err != nil {
		return err
	}
	defer m.client.Close()

	injectorConfig := vaultinjector.Config{
		TransitKeyID:     m.config.TransitKeyID,
		TransitPath:      m.config.TransitPath,
		TransitBatchSize: m.config.TransitBatchSize,
	}
	injector := vaultinjector.NewSecretInjector(injectorConfig, m.client, nil, m.logger)

	if value, ok := mutateRequest.Secret.Data[corev1.DockerConfigJsonKey]; ok {
		var dc common.DockerCredentials
		err := json.Unmarshal(value, &dc)
		if err != nil {
			return errors.Wrap(err, "unmarshal dockerconfig json failed")
		}

		err = mutateDockerCreds(mutateRequest.Secret, &dc, &injector)
		if err != nil {
			return errors.Wrap(err, "mutate dockerconfig json failed")
		}
	}

	err = mutateSecretData(mutateRequest.Secret, &injector)
	if err != nil {
		return errors.Wrap(err, "mutate generic secret failed")
	}

	return nil
}

func mutateDockerCreds(secret *corev1.Secret, dc *common.DockerCredentials, injector *vaultinjector.SecretInjector) error {
	assembled := common.DockerCredentials{Auths: map[string]common.DockerAuthConfig{}}

	for key, creds := range dc.Auths {
		authBytes, err := base64.StdEncoding.DecodeString(creds.Auth.(string))
		if err != nil {
			return errors.Wrap(err, "auth base64 decoding failed")
		}

		if isValidPrefix(string(authBytes)) {
			authCreds, err := determineAuthType(authBytes)
			if err != nil {
				return errors.Wrap(err, "handling auth failed")
			}

			credentialData, err := common.AssembleCredentialData(authCreds)
			if err != nil {
				return errors.Wrap(err, "assembling credential data failed")
			}

			dcCreds, err := injector.GetDataFromVault(credentialData)
			if err != nil {
				return errors.Wrap(err, "retrieving data from vault failed")
			}

			assembled.Auths[key] = common.AssembleDockerAuthConfig(dcCreds)
		}
	}

	marshaled, err := json.Marshal(assembled)
	if err != nil {
		return errors.Wrap(err, "marshaling dockerconfig failed")
	}

	secret.Data[corev1.DockerConfigJsonKey] = marshaled

	return nil
}

func mutateSecretData(secret *corev1.Secret, injector *vaultinjector.SecretInjector) error {
	convertedData := make(map[string]string, len(secret.Data))
	for k := range secret.Data {
		convertedData[k] = string(secret.Data[k])
	}

	convertedData, err := injector.GetDataFromVault(convertedData)
	if err != nil {
		return err
	}

	for k := range secret.Data {
		secret.Data[k] = []byte(convertedData[k])
	}

	return nil
}

func secretNeedsMutation(secret *corev1.Secret) (bool, error) {
	for key, value := range secret.Data {
		if key == corev1.DockerConfigJsonKey {
			var dc common.DockerCredentials
			err := json.Unmarshal(value, &dc)
			if err != nil {
				return false, errors.Wrap(err, "unmarshal dockerconfig json failed")
			}

			for _, creds := range dc.Auths {
				switch creds.Auth.(type) {
				case string:
					authBytes, err := base64.StdEncoding.DecodeString(creds.Auth.(string))
					if err != nil {
						return false, errors.Wrap(err, "auth base64 decoding failed")
					}

					auth := string(authBytes)
					if isValidPrefix(auth) {
						return true, nil
					}

				case map[string]interface{}:
					// get sub-keys from the auth field
					authMap, ok := creds.Auth.(map[string]interface{})
					if !ok {
						return false, errors.New("invalid auth type")
					}

					// check if any of the sub-keys have a vault prefix
					for _, v := range authMap {
						if isValidPrefix(v.(string)) {
							return true, nil
						}
					}
					return false, nil

				default:
					return false, errors.New("invalid auth type")
				}
			}

		} else if isValidPrefix(string(value)) {
			return true, nil
		} else if vaultinjector.HasInlineVaultDelimiters(string(value)) {
			return true, nil
		}
	}

	return false, nil
}

// determineAuthType takes a byte slice of authentication data and determines its type.
// It supports three formats: "username:usr:password:pass", JSON keys, and valid vault paths.
func determineAuthType(auth []byte) (map[string]string, error) {
	creds := make(map[string]string)

	// if the auth string is formatted as "username:usr:password:pass",
	// split the string into username and password
	split := strings.Split(string(auth), ":")
	if len(split) == 4 {
		creds["username"] = fmt.Sprintf("%s:%s", split[0], split[1])
		creds["password"] = fmt.Sprintf("%s:%s", split[2], split[3])

		return creds, nil
	}

	// if the auth string is a JSON key, don't split and use it as is
	if json.Valid(auth) {
		creds["auth"] = string(auth)
		return creds, nil
	}

	// if none of the above, the auth string can still be a valid vault path
	if isValidPrefix(string(auth)) {
		creds["auth"] = string(auth)
		return creds, nil
	}

	return nil, errors.New("invalid auth string")
}
