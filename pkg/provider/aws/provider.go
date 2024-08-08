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
	"log/slog"
	"strings"

	"emperror.dev/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/bank-vaults/secrets-webhook/pkg/provider"
)

const ProviderName = "aws"

type Provider struct{}

func (p *Provider) NewMutator(obj metav1.Object, logger *slog.Logger) (provider.Mutator, error) {
	config, err := loadConfig(obj)
	if err != nil {
		return nil, errors.Wrap(err, "could not load AWS configuration")
	}

	return &mutator{
		config: &config,
		logger: logger,
	}, nil
}

func isValidPrefix(value string) bool {
	return strings.HasPrefix(value, "arn:aws:secretsmanager:") || strings.HasPrefix(value, "arn:aws:ssm:")
}

func isValidPrefixWithStoreType(value string) (bool, string) {
	switch {
	case strings.HasPrefix(value, "arn:aws:secretsmanager:"):
		return true, "sm"

	case strings.HasPrefix(value, "arn:aws:ssm:"):
		return true, "ssm"

	default:
		return false, ""
	}
}
