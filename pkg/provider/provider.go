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

package provider

import (
	"context"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/bank-vaults/secrets-webhook/pkg/common"
)

type Provider interface {
	MutatePod(ctx context.Context, pod *corev1.Pod, appConfig common.AppConfig, secretInitConfig common.SecretInitConfig, dryRun bool) error
	MutateSecret(secret *corev1.Secret) error
	MutateConfigMap(configMap *corev1.ConfigMap) error
	MutateObject(obj *unstructured.Unstructured) error
}
