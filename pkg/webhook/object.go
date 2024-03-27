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
	"fmt"
	"strings"

	"emperror.dev/errors"
	"github.com/bank-vaults/internal/pkg/baoinjector"
	"github.com/bank-vaults/internal/pkg/vaultinjector"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/bank-vaults/secrets-webhook/pkg/common"
	"github.com/bank-vaults/secrets-webhook/pkg/provider/bao"
	"github.com/bank-vaults/secrets-webhook/pkg/provider/vault"
)

type element interface {
	Set(v interface{})
	Get() interface{}
}

type iterator <-chan element

type mapElement struct {
	m map[string]interface{}
	k string
}

func (e *mapElement) Set(v interface{}) {
	e.m[e.k] = v
}

func (e *mapElement) Get() interface{} {
	return e.m[e.k]
}

type sliceElement struct {
	s []interface{}
	i int
}

func (e *sliceElement) Set(v interface{}) {
	e.s[e.i] = v
}

func (e *sliceElement) Get() interface{} {
	return e.s[e.i]
}

func mapIterator(m map[string]interface{}) iterator {
	c := make(chan element, len(m))
	for k := range m {
		c <- &mapElement{k: k, m: m}
	}
	close(c)

	return c
}

func sliceIterator(s []interface{}) iterator {
	c := make(chan element, len(s))
	for i := range s {
		c <- &sliceElement{i: i, s: s}
	}
	close(c)

	return c
}

func (mw *MutatingWebhook) MutateObject(object *unstructured.Unstructured) error {
	mw.logger.Debug(fmt.Sprintf("mutating object: %s.%s", object.GetNamespace(), object.GetName()))

	for _, config := range mw.providerConfigs {
		switch providerConfig := config.(type) {
		case vault.Config:
			currentlyUsedProvider = vault.ProviderName

			err := mw.mutateObjectForVault(object, providerConfig)
			if err != nil {
				return errors.Wrap(err, "failed to mutate secret")
			}

		case bao.Config:
			currentlyUsedProvider = bao.ProviderName

			err := mw.mutateObjectForBao(object, providerConfig)
			if err != nil {
				return errors.Wrap(err, "failed to mutate secret")
			}

		default:
			return errors.Errorf("unknown provider config type: %T", config)
		}
	}

	return nil
}

// ======== VAULT ========

func (mw *MutatingWebhook) mutateObjectForVault(object *unstructured.Unstructured, vaultConfig vault.Config) error {
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

	return traverseObjectForVault(object.Object, &injector)
}

func traverseObjectForVault(o interface{}, injector *vaultinjector.SecretInjector) error {
	var iterator iterator

	switch value := o.(type) {
	case map[string]interface{}:
		iterator = mapIterator(value)
	case []interface{}:
		iterator = sliceIterator(value)
	default:
		return nil
	}

	for e := range iterator {
		switch s := e.Get().(type) {
		case string:
			if common.HasVaultPrefix(s) {
				dataFromVault, err := injector.GetDataFromVault(map[string]string{"data": s})
				if err != nil {
					return err
				}

				e.Set(dataFromVault["data"])
			} else if vaultinjector.HasInlineVaultDelimiters(s) {
				dataFromVault := s
				for _, vaultSecretReference := range vaultinjector.FindInlineVaultDelimiters(s) {
					mapData, err := injector.GetDataFromVault(map[string]string{"data": vaultSecretReference[1]})
					if err != nil {
						return err
					}
					dataFromVault = strings.Replace(dataFromVault, vaultSecretReference[0], mapData["data"], -1)
				}

				e.Set(dataFromVault)
			}

		case map[string]interface{}, []interface{}:
			err := traverseObjectForVault(e.Get(), injector)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

// ======== BAO ========

func (mw *MutatingWebhook) mutateObjectForBao(object *unstructured.Unstructured, baoConfig bao.Config) error {
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

	return traverseObjectForBao(object.Object, &injector)
}

func traverseObjectForBao(o interface{}, injector *baoinjector.SecretInjector) error {
	var iterator iterator

	switch value := o.(type) {
	case map[string]interface{}:
		iterator = mapIterator(value)
	case []interface{}:
		iterator = sliceIterator(value)
	default:
		return nil
	}

	for e := range iterator {
		switch s := e.Get().(type) {
		case string:
			if common.HasBaoPrefix(s) {
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
			err := traverseObjectForBao(e.Get(), injector)
			if err != nil {
				return err
			}
		}
	}

	return nil
}
