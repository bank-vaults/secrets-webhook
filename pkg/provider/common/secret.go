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

package common

import (
	"encoding/base64"
	"fmt"
)

type DockerCredentials struct {
	Auths map[string]DockerAuthConfig `json:"auths"`
}

// DockerAuthConfig contains authorization information for connecting to a Registry
type DockerAuthConfig struct {
	Username string      `json:"username,omitempty"`
	Password string      `json:"password,omitempty"`
	Auth     interface{} `json:"auth,omitempty"`

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

// assembleCredentialData assembles the credential data that will be retrieved from Vault
func AssembleCredentialData(authCreds map[string]string) (map[string]string, error) {
	if username, ok := authCreds["username"]; ok {
		if password, ok := authCreds["password"]; ok {
			return map[string]string{
				"username": username,
				"password": password,
			}, nil
		}
	}

	if auth, ok := authCreds["auth"]; ok {
		return map[string]string{
			"auth": auth,
		}, nil
	}

	return nil, fmt.Errorf("no valid credentials found")
}

// assembleDockerAuthConfig assembles the DockerAuthConfig from the retrieved data from Vault
func AssembleDockerAuthConfig(dcCreds map[string]string) DockerAuthConfig {
	if username, ok := dcCreds["username"]; ok {
		if password, ok := dcCreds["password"]; ok {
			return DockerAuthConfig{
				Username: username,
				Password: password,
				Auth:     base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", username, password))),
			}
		}
	}

	if auth, ok := dcCreds["auth"]; ok {
		return DockerAuthConfig{
			Auth: base64.StdEncoding.EncodeToString([]byte(auth)),
		}
	}

	return DockerAuthConfig{}
}
