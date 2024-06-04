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

package bao

import (
	"context"
	"fmt"
	"strings"

	"github.com/bank-vaults/internal/pkg/baoinjector"

	"github.com/bank-vaults/secrets-webhook/pkg/provider"
	"github.com/bank-vaults/secrets-webhook/pkg/provider/common"
)

func (m *mutator) MutateObject(ctx context.Context, mutateRequest provider.ObjectMutateRequest) error {
	m.logger.Debug(fmt.Sprintf("mutating object: %s.%s", mutateRequest.Object.GetNamespace(), mutateRequest.Object.GetName()))

	err := m.newClient(ctx, mutateRequest.K8sClient, mutateRequest.K8sNamespace)
	if err != nil {
		return err
	}
	defer m.client.Close()

	injectorConfig := baoinjector.Config{
		TransitKeyID:     m.config.TransitKeyID,
		TransitPath:      m.config.TransitPath,
		TransitBatchSize: m.config.TransitBatchSize,
	}
	injector := baoinjector.NewSecretInjector(injectorConfig, m.client, nil, m.logger)

	return traverseObject(mutateRequest.Object.Object, &injector)
}

func traverseObject(o interface{}, injector *baoinjector.SecretInjector) error {
	var iterator common.Iterator

	switch value := o.(type) {
	case map[string]interface{}:
		iterator = common.MapIterator(value)

	case []interface{}:
		iterator = common.SliceIterator(value)

	default:
		return nil
	}

	for e := range iterator {
		switch s := e.Get().(type) {
		case string:
			if isValidPrefix(s) {
				dataFromBao, err := injector.GetDataFromBao(map[string]string{"data": s})
				if err != nil {
					return err
				}

				e.Set(dataFromBao["data"])
			} else if baoinjector.HasInlineBaoDelimiters(s) {
				dataFromBao := s
				for _, baoSecretReference := range baoinjector.FindInlineBaoDelimiters(s) {
					mapData, err := injector.GetDataFromBao(map[string]string{"data": baoSecretReference[1]})
					if err != nil {
						return err
					}

					dataFromBao = strings.Replace(dataFromBao, baoSecretReference[0], mapData["data"], -1)
				}

				e.Set(dataFromBao)
			}

		case map[string]interface{}, []interface{}:
			err := traverseObject(e.Get(), injector)
			if err != nil {
				return err
			}
		}
	}

	return nil
}
