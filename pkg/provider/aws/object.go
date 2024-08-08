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
	"fmt"

	"github.com/bank-vaults/secrets-webhook/pkg/provider"
	"github.com/bank-vaults/secrets-webhook/pkg/provider/common"
)

func (m *mutator) MutateObject(ctx context.Context, mutateRequest provider.ObjectMutateRequest) error {
	m.logger.Debug(fmt.Sprintf("mutating object: %s.%s", mutateRequest.Object.GetNamespace(), mutateRequest.Object.GetName()))

	err := m.newClient(ctx, mutateRequest.K8sClient)
	if err != nil {
		return fmt.Errorf("creating AWS clients failed: %w", err)
	}

	return traverseObject(ctx, mutateRequest.Object.Object, *m.client)
}

func traverseObject(ctx context.Context, o interface{}, client client) error {
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
			if valid, storeType := isValidPrefixWithStoreType(s); valid {
				dataFromStore, err := getDataFromStore(ctx, client, storeType, map[string]string{"data": s})
				if err != nil {
					return fmt.Errorf("failed to get data from store: %w", err)
				}

				e.Set(dataFromStore["data"])
			}

		case map[string]interface{}, []interface{}:
			err := traverseObject(ctx, e.Get(), client)
			if err != nil {
				return fmt.Errorf("failed to traverse object: %w", err)
			}
		}
	}

	return nil
}
