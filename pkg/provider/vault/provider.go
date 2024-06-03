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
	"log/slog"
	"strings"

	"emperror.dev/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/bank-vaults/secrets-webhook/pkg/provider"
)

const (
	// AgentConfig is a string that represents the configuration for the Vault agent.
	// It includes the path to the pid file, and the configuration for automatic authentication.
	// The automatic authentication is configured to use the Kubernetes method,
	// with a specified namespace, mount path, and role.
	// The configuration also includes a sink of type "file", which specifies the path
	// to the token that the Vault agent will use for authentication.
	// This part of the code is called when the 'UseAgent' annotation is set to true.
	// When 'UseAgent' is true, the Vault agent is used for handling Vault authentication and token renewal.
	// This ConfigMap, created in the active selection, is necessary for its configuration.
	// It sets the name of the ConfigMap, assigns the owner references, and populates the data with the agent configuration.
	// The agent configuration is formatted with the Vault namespace, path, and role specified in the manager's configuration.
	AgentConfig = `
	pid_file = "/tmp/pidfile"
	
	auto_auth {
			method "kubernetes" {
					namespace = "%s"
					mount_path = "auth/%s"
					config = {
							role = "%s"
					}
			}
	
			sink "file" {
					config = {
							path = "/vault/.vault-token"
					}
			}
	}`

	ProviderName = "vault"
)

type Provider struct{}

func (*Provider) NewMutator(obj metav1.Object, logger *slog.Logger) (provider.Mutator, error) {
	config, err := loadConfig(obj)
	if err != nil {
		return nil, errors.Wrap(err, "failed to load Vault configuration")
	}

	return &mutator{config: &config, logger: logger}, nil
}

func isValidPrefix(value string) bool {
	return strings.HasPrefix(value, "vault:") || strings.HasPrefix(value, ">>vault:")
}
