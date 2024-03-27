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
	"encoding/json"
	"fmt"
	"strings"

	"emperror.dev/errors"
	"github.com/bank-vaults/internal/pkg/baoinjector"
	"github.com/bank-vaults/internal/pkg/vaultinjector"
	corev1 "k8s.io/api/core/v1"

	"github.com/bank-vaults/secrets-webhook/pkg/common"
	"github.com/bank-vaults/secrets-webhook/pkg/provider/bao"
	"github.com/bank-vaults/secrets-webhook/pkg/provider/vault"
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

func (mw *MutatingWebhook) MutateSecret(secret *corev1.Secret) error {
	for _, config := range mw.providerConfigs {
		switch providerConfig := config.(type) {
		case vault.Config:
			currentlyUsedProvider = vault.ProviderName

			err := mw.mutateSecretForVault(secret, providerConfig)
			if err != nil {
				return errors.Wrap(err, "failed to mutate secret")
			}

		case bao.Config:
			currentlyUsedProvider = bao.ProviderName

			err := mw.mutateSecretForBao(secret, providerConfig)
			if err != nil {
				return errors.Wrap(err, "failed to mutate secret")
			}

		default:
			return errors.Errorf("unknown provider config type: %T", config)
		}
	}

	return nil
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
				if hasProviderPrefix(currentlyUsedProvider, auth, false) {
					return true, nil
				}
			}

		} else if hasProviderPrefix(currentlyUsedProvider, string(value), false) {
			return true, nil
		} else if hasInlineProviderDelimiters(currentlyUsedProvider, string(value)) {
			return true, nil
		}
	}

	return false, nil
}

// ======== VAULT ========

func (mw *MutatingWebhook) mutateSecretForVault(secret *corev1.Secret, vaultConfig vault.Config) error {
	// do an early exit if no mutation is needed
	requiredToMutate, err := secretNeedsMutation(secret)
	if err != nil {
		return errors.Wrap(err, "failed to check if secret needs to be mutated")
	}

	if !requiredToMutate {
		return nil
	}

	vaultClient, err := mw.newVaultClient(vaultConfig)
	if err != nil {
		return errors.Wrap(err, "failed to create vault client")
	}
	defer vaultClient.Close()

	injectorConfig := vaultinjector.Config{
		TransitKeyID:     vaultConfig.TransitKeyID,
		TransitPath:      vaultConfig.TransitPath,
		TransitBatchSize: vaultConfig.TransitBatchSize,
	}
	injector := vaultinjector.NewSecretInjector(injectorConfig, vaultClient, nil, logger)

	if value, ok := secret.Data[corev1.DockerConfigJsonKey]; ok {
		var dc dockerCredentials
		err := json.Unmarshal(value, &dc)
		if err != nil {
			return errors.Wrap(err, "unmarshal dockerconfig json failed")
		}

		err = mw.mutateDockerCredsForVault(secret, &dc, &injector)
		if err != nil {
			return errors.Wrap(err, "mutate dockerconfig json failed")
		}
	}

	err = mw.mutateSecretDataForVault(secret, &injector)
	if err != nil {
		return errors.Wrap(err, "mutate generic secret failed")
	}

	return nil
}

func (mw *MutatingWebhook) mutateDockerCredsForVault(secret *corev1.Secret, dc *dockerCredentials, injector *vaultinjector.SecretInjector) error {
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

			dcCreds, err := injector.GetDataFromVault(credentialData)
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

func (mw *MutatingWebhook) mutateSecretDataForVault(secret *corev1.Secret, injector *vaultinjector.SecretInjector) error {
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

// ======== BAO ========

func (mw *MutatingWebhook) mutateSecretForBao(secret *corev1.Secret, baoConfig bao.Config) error {
	// do an early exit if no mutation is needed
	requiredToMutate, err := secretNeedsMutation(secret)
	if err != nil {
		return errors.Wrap(err, "failed to check if secret needs to be mutated")
	}

	if !requiredToMutate {
		return nil
	}

	baoClient, err := mw.newBaoClient(baoConfig)
	if err != nil {
		return errors.Wrap(err, "failed to create bao client")
	}
	defer baoClient.Close()

	injectorConfig := baoinjector.Config{
		TransitKeyID:     baoConfig.TransitKeyID,
		TransitPath:      baoConfig.TransitPath,
		TransitBatchSize: baoConfig.TransitBatchSize,
	}
	injector := baoinjector.NewSecretInjector(injectorConfig, baoClient, nil, logger)

	if value, ok := secret.Data[corev1.DockerConfigJsonKey]; ok {
		var dc dockerCredentials
		err := json.Unmarshal(value, &dc)
		if err != nil {
			return errors.Wrap(err, "unmarshal dockerconfig json failed")
		}

		err = mw.mutateDockerCredsForBao(secret, &dc, &injector)
		if err != nil {
			return errors.Wrap(err, "mutate dockerconfig json failed")
		}
	}

	err = mw.mutateSecretDataForBao(secret, &injector)
	if err != nil {
		return errors.Wrap(err, "mutate generic secret failed")
	}

	return nil
}

func (mw *MutatingWebhook) mutateDockerCredsForBao(secret *corev1.Secret, dc *dockerCredentials, injector *baoinjector.SecretInjector) error {
	assembled := dockerCredentials{Auths: map[string]dockerAuthConfig{}}

	for key, creds := range dc.Auths {
		authBytes, err := base64.StdEncoding.DecodeString(creds.Auth)
		if err != nil {
			return errors.Wrap(err, "auth base64 decoding failed")
		}

		auth := string(authBytes)
		if common.HasBaoPrefix(auth) {
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

			dcCreds, err := injector.GetDataFromBao(credentialData)
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

func (mw *MutatingWebhook) mutateSecretDataForBao(secret *corev1.Secret, injector *baoinjector.SecretInjector) error {
	convertedData := make(map[string]string, len(secret.Data))
	for k := range secret.Data {
		convertedData[k] = string(secret.Data[k])
	}

	convertedData, err := injector.GetDataFromBao(convertedData)
	if err != nil {
		return err
	}

	for k := range secret.Data {
		secret.Data[k] = []byte(convertedData[k])
	}

	return nil
}
