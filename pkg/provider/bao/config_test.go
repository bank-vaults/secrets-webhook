// Copyright © 2026 Bank-Vaults Maintainers
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
	"os"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/bank-vaults/secrets-webhook/pkg/common"
)

func TestLoadConfig_AddressHardening(t *testing.T) {
	tests := []struct {
		name           string
		annotations    map[string]string
		envVars        map[string]string
		wantErr        bool
		wantAddr       string
		wantSkipVerify bool
	}{
		{
			name: "object addr override rejected when not in allowlist",
			annotations: map[string]string{
				common.BaoAddrAnnotation: "https://evil.attacker.com",
			},
			wantErr: true,
		},
		{
			name: "object addr override rejected for IMDS link-local",
			annotations: map[string]string{
				common.BaoAddrAnnotation: "http://169.254.169.254/latest/meta-data/",
			},
			envVars: map[string]string{
				common.BaoAddrAllowlistEnvVar: "http://169.254.169.254/latest/meta-data/",
			},
			wantErr: true,
		},
		{
			name: "object addr override accepted when allowlisted",
			annotations: map[string]string{
				common.BaoAddrAnnotation: "https://bao.prod.svc:8300",
			},
			envVars: map[string]string{
				common.BaoAddrAllowlistEnvVar: "https://bao.prod.svc:8300",
			},
			wantErr:  false,
			wantAddr: "https://bao.prod.svc:8300",
		},
		{
			name:        "operator-configured addr is trusted and never validated",
			annotations: map[string]string{},
			envVars: map[string]string{
				common.BaoAddrEnvVar: "https://10.0.0.5:8300",
			},
			wantErr:  false,
			wantAddr: "https://10.0.0.5:8300",
		},
		{
			name: "object skip-verify ignored by default",
			annotations: map[string]string{
				common.BaoAddrAnnotation:       "https://bao.prod.svc:8300",
				common.BaoSkipVerifyAnnotation: "true",
			},
			envVars: map[string]string{
				common.BaoAddrAllowlistEnvVar: "https://bao.prod.svc:8300",
			},
			wantErr:        false,
			wantAddr:       "https://bao.prod.svc:8300",
			wantSkipVerify: false,
		},
		{
			name: "object skip-verify honored when operator opts in",
			annotations: map[string]string{
				common.BaoAddrAnnotation:       "https://bao.prod.svc:8300",
				common.BaoSkipVerifyAnnotation: "true",
			},
			envVars: map[string]string{
				common.BaoAddrAllowlistEnvVar:         "https://bao.prod.svc:8300",
				common.BaoAllowObjectSkipVerifyEnvVar: "true",
			},
			wantErr:        false,
			wantAddr:       "https://bao.prod.svc:8300",
			wantSkipVerify: true,
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

			config, err := LoadConfig(&metav1.ObjectMeta{Annotations: ttp.annotations})
			if ttp.wantErr {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)
			assert.Equal(t, ttp.wantAddr, config.Addr)
			assert.Equal(t, ttp.wantSkipVerify, config.SkipVerify)
		})
	}
}
