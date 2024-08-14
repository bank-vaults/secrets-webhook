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

package aws

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go/aws/arn"
	corev1 "k8s.io/api/core/v1"

	"github.com/bank-vaults/secrets-webhook/pkg/provider"
	"github.com/bank-vaults/secrets-webhook/pkg/provider/common"
)

func (m *mutator) MutateSecret(ctx context.Context, mutateRequest provider.SecretMutateRequest) error {
	// do an early exit if no mutation is needed
	requiredToMutate, storeType, err := secretNeedsMutation(mutateRequest.Secret)
	if err != nil {
		return fmt.Errorf("checking if secret needs mutation failed: %w", err)
	}

	if !requiredToMutate {
		return nil
	}

	err = m.newClient(ctx, mutateRequest.K8sClient)
	if err != nil {
		return fmt.Errorf("creating AWS clients failed: %w", err)
	}

	if value, ok := mutateRequest.Secret.Data[corev1.DockerConfigJsonKey]; ok {
		var dc common.DockerCredentials
		err := json.Unmarshal(value, &dc)
		if err != nil {
			return fmt.Errorf("unmarshal dockerconfig json failed: %w", err)
		}

		err = mutateDockerCreds(ctx, mutateRequest.Secret, *m.client, storeType, &dc)
		if err != nil {
			return fmt.Errorf("mutate docker creds failed: %w", err)
		}
	}

	err = mutateSecretData(ctx, mutateRequest.Secret, *m.client, storeType)
	if err != nil {
		return fmt.Errorf("mutate secret data failed: %w", err)
	}

	return nil
}

func mutateDockerCreds(ctx context.Context, secret *corev1.Secret, storeClient client, storeType string, dc *common.DockerCredentials) error {
	assembled := common.DockerCredentials{Auths: map[string]common.DockerAuthConfig{}}
	for key, creds := range dc.Auths {
		authBytes, err := base64.StdEncoding.DecodeString(creds.Auth.(string))
		if err != nil {
			return fmt.Errorf("auth base64 decoding failed: %w", err)
		}

		if isValidPrefix(string(authBytes)) {
			authCreds, err := determineAuthType(authBytes)
			if err != nil {
				return fmt.Errorf("determining auth type failed: %w", err)
			}

			credentialData, err := common.AssembleCredentialData(authCreds)
			if err != nil {
				return fmt.Errorf("assembling credential data failed: %w", err)
			}

			dcCreds, err := getDataFromStore(ctx, storeClient, storeType, credentialData)
			if err != nil {
				return fmt.Errorf("getting data from store failed: %w", err)
			}

			dcCreds, err = checkOtherStoreForSecrets(ctx, storeClient, dcCreds)
			if err != nil {
				return fmt.Errorf("checking other store for secrets failed: %w", err)
			}

			assembled.Auths[key] = common.AssembleDockerAuthConfig(dcCreds)
		}
	}

	marshaled, err := json.Marshal(assembled)
	if err != nil {
		return fmt.Errorf("marshal dockerconfig json failed: %w", err)
	}

	secret.Data[corev1.DockerConfigJsonKey] = marshaled

	return nil
}

func mutateSecretData(ctx context.Context, secret *corev1.Secret, storeClient client, storeType string) error {
	data := make(map[string]string, len(secret.Data))
	for k := range secret.Data {
		data[k] = string(secret.Data[k])
	}

	convertedData, err := getDataFromStore(ctx, storeClient, storeType, data)
	if err != nil {
		return fmt.Errorf("getting data from store failed: %w", err)
	}

	convertedData, err = checkOtherStoreForSecrets(ctx, storeClient, convertedData)
	if err != nil {
		return fmt.Errorf("checking other store for secrets failed: %w", err)
	}

	for k := range secret.Data {
		secret.Data[k] = []byte(convertedData[k])
	}

	return nil
}

func secretNeedsMutation(secret *corev1.Secret) (bool, string, error) {
	for key, value := range secret.Data {
		if key == corev1.DockerConfigJsonKey {
			var dc common.DockerCredentials
			err := json.Unmarshal(value, &dc)
			if err != nil {
				return false, "", fmt.Errorf("unmarshal dockerconfig json failed: %w", err)
			}

			for _, creds := range dc.Auths {
				switch creds.Auth.(type) {
				case string:
					authBytes, err := base64.StdEncoding.DecodeString(creds.Auth.(string))
					if err != nil {
						return false, "", fmt.Errorf("auth base64 decoding failed: %w", err)
					}

					if valid, storeType := isValidPrefixWithStoreType(string(authBytes)); valid {
						return true, storeType, nil
					}

				case map[string]interface{}:
					// get sub-keys from the auth field
					authMap, ok := creds.Auth.(map[string]interface{})
					if !ok {
						return false, "", fmt.Errorf("invalid auth type")
					}

					// check if any of the sub-keys have a valid prefix
					for _, v := range authMap {
						if valid, storeType := isValidPrefixWithStoreType(v.(string)); valid {
							return true, storeType, nil
						}
					}
					return false, "", nil

				default:
					return false, "", fmt.Errorf("invalid auth type")
				}
			}

		} else if valid, storeType := isValidPrefixWithStoreType(string(value)); valid {
			return true, storeType, nil
		}
	}

	return false, "", nil
}

// determineAuthType takes a byte slice of authentication data and determines its type.
// It supports three formats: "usr:pass", JSON keys, and valid ARN's.
func determineAuthType(auth []byte) (map[string]string, error) {
	creds := make(map[string]string)

	// if the auth string is formatted as "usr:pass",
	// split the string into username and password
	parts := strings.Split(string(auth), ":")
	for i := 1; i < len(parts); i++ {
		username := strings.Join(parts[:i], ":")
		password := strings.Join(parts[i:], ":")

		if arn.IsARN(username) && arn.IsARN(password) {
			creds["username"] = username
			creds["password"] = password

			return creds, nil
		}
	}

	// if the auth string is a JSON key, don't split and use it as is
	if json.Valid(auth) {
		creds["auth"] = string(auth)
		return creds, nil
	}

	// if none of the above, the auth string can still be a valid AWS ARN
	if arn.IsARN(string(auth)) {
		creds["auth"] = string(auth)
		return creds, nil
	}

	return nil, fmt.Errorf("invalid auth type")
}
