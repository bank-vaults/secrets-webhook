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

package vault

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"

	"emperror.dev/errors"
	"github.com/bank-vaults/internal/injector"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/bank-vaults/secrets-webhook/pkg/common"
)

type dockerCredentials struct {
	Auths map[string]dockerAuthConfig `json:"auths"`
}

// dockerAuthConfig contains authorization information for connecting to a Registry
type dockerAuthConfig struct {
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
	Auth     string `json:"auth,omitempty"`

	// Email is an optional value associated with the username.
	// This field is deprecated and will be removed in a later
	// version of docker.
	Email string `json:"email,omitempty"`

	ServerAddress string `json:"serveraddress,omitempty"`

	// IdentityToken is used to authenticate the user and get
	// an access token for the registry.
	IdentityToken string `json:"identitytoken,omitempty"`

	// RegistryToken is a bearer token to be sent to a registry
	RegistryToken string `json:"registrytoken,omitempty"`
}

func secretNeedsMutation(secret *corev1.Secret) (bool, error) {
	for key, value := range secret.Data {
		if key == corev1.DockerConfigJsonKey {
			var dc dockerCredentials
			err := json.Unmarshal(value, &dc)
			if err != nil {
				return false, errors.Wrap(err, "unmarshal dockerconfig json failed")
			}

			for _, creds := range dc.Auths {
				authBytes, err := base64.StdEncoding.DecodeString(creds.Auth)
				if err != nil {
					return false, errors.Wrap(err, "auth base64 decoding failed")
				}

				auth := string(authBytes)
				if common.HasVaultPrefix(auth) {
					return true, nil
				}
			}
		} else if common.HasVaultPrefix(string(value)) {
			return true, nil
		} else if injector.HasInlineVaultDelimiters(string(value)) {
			return true, nil
		}
	}
	return false, nil
}

func secretMutator(secret *corev1.Secret, config Config, k8sClient kubernetes.Interface, namespace string, logger *slog.Logger) error {
	// do an early exit and don't construct the Vault client if not needed
	requiredToMutate, err := secretNeedsMutation(secret)
	if err != nil {
		return errors.Wrap(err, "failed to check if secret needs to be mutated")
	}

	if !requiredToMutate {
		return nil
	}

	client, err := NewClient(k8sClient, namespace, config)
	if err != nil {
		return errors.Wrap(err, "failed to create Vault client")
	}

	defer client.Close()

	injectorConfig := injector.Config{
		TransitKeyID:     config.TransitKeyID,
		TransitPath:      config.TransitPath,
		TransitBatchSize: config.TransitBatchSize,
	}
	secretInjector := injector.NewSecretInjector(injectorConfig, client, nil, logger)

	if value, ok := secret.Data[corev1.DockerConfigJsonKey]; ok {
		var dc dockerCredentials
		err := json.Unmarshal(value, &dc)
		if err != nil {
			return errors.Wrap(err, "unmarshal dockerconfig json failed")
		}
		err = mutateDockerCreds(secret, &dc, &secretInjector)
		if err != nil {
			return errors.Wrap(err, "mutate dockerconfig json failed")
		}
	}

	err = mutateSecretData(secret, &secretInjector)
	if err != nil {
		return errors.Wrap(err, "mutate generic secret failed")
	}

	return nil
}

func mutateDockerCreds(secret *corev1.Secret, dc *dockerCredentials, secretInjector *injector.SecretInjector) error {
	assembled := dockerCredentials{Auths: map[string]dockerAuthConfig{}}

	for key, creds := range dc.Auths {
		authBytes, err := base64.StdEncoding.DecodeString(creds.Auth)
		if err != nil {
			return errors.Wrap(err, "auth base64 decoding failed")
		}

		auth := string(authBytes)
		if common.HasVaultPrefix(auth) {
			split := strings.Split(auth, ":")
			if len(split) != 4 {
				return errors.New("splitting auth credentials failed")
			}
			username := fmt.Sprintf("%s:%s", split[0], split[1])
			password := fmt.Sprintf("%s:%s", split[2], split[3])

			credentialData := map[string]string{
				"username": username,
				"password": password,
			}

			dcCreds, err := secretInjector.GetDataFromVault(credentialData)
			if err != nil {
				return err
			}
			auth = fmt.Sprintf("%s:%s", dcCreds["username"], dcCreds["password"])
			dockerAuth := dockerAuthConfig{
				Auth: base64.StdEncoding.EncodeToString([]byte(auth)),
			}
			if creds.Username != "" && creds.Password != "" {
				dockerAuth.Username = dcCreds["username"]
				dockerAuth.Password = dcCreds["password"]
			}
			assembled.Auths[key] = dockerAuth
		}
	}

	marshaled, err := json.Marshal(assembled)
	if err != nil {
		return errors.Wrap(err, "marshaling dockerconfig failed")
	}

	secret.Data[corev1.DockerConfigJsonKey] = marshaled

	return nil
}

func mutateSecretData(secret *corev1.Secret, secretInjector *injector.SecretInjector) error {
	convertedData := make(map[string]string, len(secret.Data))

	for k := range secret.Data {
		convertedData[k] = string(secret.Data[k])
	}

	convertedData, err := secretInjector.GetDataFromVault(convertedData)
	if err != nil {
		return err
	}

	for k := range secret.Data {
		secret.Data[k] = []byte(convertedData[k])
	}

	return nil
}
