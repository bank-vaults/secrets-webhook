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

	corev1 "k8s.io/api/core/v1"
)

func MutateConfigMapBinaryData(configMap *corev1.ConfigMap, mapData map[string]string) error {
	for key, value := range mapData {
		// NOTE: If the binary data is stored in base64 by the provider,
		// we need to base64 decode it since Kubernetes will encode this data too.

		// Check if the value is base64 encoded by trying to decode it
		valueBytes, err := base64.StdEncoding.DecodeString(value)
		if err != nil {
			// If the value is not base64 encoded, use the value as is
			configMap.Data[key] = value
		} else {
			// If the value is base64 encoded, use the decoded value
			configMap.BinaryData[key] = valueBytes
		}
	}

	return nil
}
