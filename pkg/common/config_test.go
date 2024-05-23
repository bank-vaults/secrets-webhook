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
	"os"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestLoadWebhookConfig(t *testing.T) {
	tests := []struct {
		name              string
		annotations       map[string]string
		envVars           map[string]string
		webhookConfigWant Config
	}{
		{
			name: "Handle deprecated webhook annotations all",
			annotations: map[string]string{
				CleanupOldAnnotationsAnnotation:                 "true",
				MutateAnnotationDeprecated:                      "false",
				PSPAllowPrivilegeEscalationAnnotationDeprecated: "true",
				RunAsNonRootAnnotationDeprecated:                "true",
				RunAsUserAnnotationDeprecated:                   "1000",
				RunAsGroupAnnotationDeprecated:                  "1000",
				ReadOnlyRootFsAnnotationDeprecated:              "true",
				RegistrySkipVerifyAnnotationDeprecated:          "true",
				MutateProbesAnnotationDeprecated:                "true",
			},
			webhookConfigWant: Config{
				Mutate:                      false,
				PspAllowPrivilegeEscalation: true,
				RunAsNonRoot:                true,
				RunAsUser:                   1000,
				RunAsGroup:                  1000,
				ReadOnlyRootFilesystem:      true,
				RegistrySkipVerify:          true,
				MutateProbes:                true,
			},
		},
		{
			name: "Should stop parsing annotations if mutate is set to skip",
			annotations: map[string]string{
				CleanupOldAnnotationsAnnotation:                 "true",
				MutateAnnotationDeprecated:                      "skip",
				PSPAllowPrivilegeEscalationAnnotationDeprecated: "true",
				RunAsGroupAnnotation:                            "1000",
				RegistrySkipVerifyAnnotationDeprecated:          "true",
			},
			webhookConfigWant: Config{
				Mutate: true,
			},
		},
	}

	for _, tt := range tests {
		ttp := tt
		t.Run(ttp.name, func(t *testing.T) {
			for key, value := range ttp.envVars {
				viper.Set(key, value)
			}
			t.Cleanup(func() {
				viper.Reset()
				os.Clearenv()
			})

			whConfig := LoadWebhookConfig(&metav1.ObjectMeta{Annotations: ttp.annotations})
			assert.Equal(t, ttp.webhookConfigWant, whConfig)
		})
	}
}
