package vault

import (
	"fmt"
	"log/slog"
	"strings"

	"github.com/bank-vaults/internal/injector"
	"github.com/bank-vaults/secrets-webhook/pkg/common"
	"github.com/bank-vaults/vault-sdk/vault"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
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

func traverseObject(o interface{}, secretInjector *injector.SecretInjector) error {
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
				dataFromVault, err := secretInjector.GetDataFromVault(map[string]string{"data": s})
				if err != nil {
					return err
				}

				e.Set(dataFromVault["data"])
			} else if injector.HasInlineVaultDelimiters(s) {
				dataFromVault := s
				for _, vaultSecretReference := range injector.FindInlineVaultDelimiters(s) {
					mapData, err := secretInjector.GetDataFromVault(map[string]string{"data": vaultSecretReference[1]})
					if err != nil {
						return err
					}
					dataFromVault = strings.Replace(dataFromVault, vaultSecretReference[0], mapData["data"], -1)
				}
				e.Set(dataFromVault)
			}
		case map[string]interface{}, []interface{}:
			err := traverseObject(e.Get(), secretInjector)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func objectMutator(obj *unstructured.Unstructured, config Config, client *vault.Client) error {
	slog.Debug(fmt.Sprintf("mutating object: %s.%s", obj.GetNamespace(), obj.GetName()))

	defer client.Close()

	injectorConfig := injector.Config{
		TransitKeyID:     config.TransitKeyID,
		TransitPath:      config.TransitPath,
		TransitBatchSize: config.TransitBatchSize,
	}
	secretInjector := injector.NewSecretInjector(injectorConfig, client, nil, slog.Default())

	return traverseObject(obj.Object, &secretInjector)
}
