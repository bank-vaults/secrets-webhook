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

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"

	appCommon "github.com/bank-vaults/secrets-webhook/pkg/common"
	"github.com/bank-vaults/secrets-webhook/pkg/provider"
	"github.com/bank-vaults/secrets-webhook/pkg/registry"
)

func (m *mutator) MutatePod(_ context.Context, _ provider.PodMutateRequest) error {
	return nil
}

func (m *mutator) MutateContainers(_ context.Context, _ []corev1.Container, _ *corev1.PodSpec, _ appCommon.Config, _ appCommon.SecretInitConfig, _ kubernetes.Interface, _ registry.ImageRegistry) (bool, error) {
	return false, nil
}
