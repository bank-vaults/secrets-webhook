// Copyright © 2025 Bank-Vaults Maintainers
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
	"testing"

	"log/slog"

	"github.com/bank-vaults/secrets-webhook/pkg/provider/common"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestNewVaultClientMetrics(t *testing.T) {
	prometheus.DefaultRegisterer.MustRegister(common.AuthAttempts)
	prometheus.DefaultRegisterer.MustRegister(common.AuthAttemptsErrors)
	logger := slog.New(slog.DiscardHandler)

	tests := []struct {
		name          string
		expectedError bool
		config        Config
		setupK8s      func(t *testing.T) *fake.Clientset
	}{
		{
			name: "successful aws session with secret",
			config: Config{
				CredentialsNamespace:  defaultCredentialsNamespace,
				CredentialsSecretName: defaultCredentialsSecretName,
			},
			setupK8s: func(t *testing.T) *fake.Clientset {
				return fake.NewSimpleClientset(
					&corev1.Secret{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "aws-credentials",
							Namespace: "default",
						},
						Data: map[string][]byte{
							"AWS_ACCESS_KEY_ID":     []byte("aws-access-key"),
							"AWS_SECRET_ACCESS_KEY": []byte("aws-secret-key"),
						},
					},
				)
			},
			expectedError: false,
		},
		{
			name:   "error when secret not found",
			config: Config{},
			setupK8s: func(t *testing.T) *fake.Clientset {
				return fake.NewSimpleClientset()
			},
			expectedError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			common.AuthAttempts.Reset()
			common.AuthAttemptsErrors.Reset()

			k8sClient := tt.setupK8s(t)
			mutator := &mutator{
				config: &tt.config,
				logger: logger,
			}

			sess, err := mutator.createAWSSession(t.Context(), k8sClient)

			assert.Equal(t, float64(1), testutil.ToFloat64(common.AuthAttempts.WithLabelValues("aws")), "AuthAttempts should be incremented")
			if tt.expectedError {
				assert.Equal(t, float64(1), testutil.ToFloat64(common.AuthAttemptsErrors.WithLabelValues("aws", "kubernetes_error")), "AuthAttemptsErrors should be incremented on error")
				assert.Error(t, err)
				assert.Nil(t, sess)
			} else {
				assert.Equal(t, float64(0), testutil.ToFloat64(common.AuthAttemptsErrors.WithLabelValues("aws", "kubernetes_error")), "AuthAttemptsErrors should not be incremented on success")
				assert.NoError(t, err)
				assert.NotNil(t, sess)
			}
		})
	}
}
