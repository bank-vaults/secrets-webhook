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
	"log/slog"
	"net/http"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/bank-vaults/secrets-webhook/pkg/provider/common"
	"github.com/hashicorp/go-cleanhttp"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

type mutator struct {
	client *client
	config *Config
	logger *slog.Logger
}

type client struct {
	sm  *secretsmanager.Client
	ssm *ssm.Client
}

func (m *mutator) newClient(ctx context.Context, k8sClient kubernetes.Interface) error {
	config, err := m.createAWSConfig(ctx, k8sClient)
	if err != nil {
		return fmt.Errorf("failed to create AWS config: %w", err)
	}

	m.client = &client{
		sm:  secretsmanager.NewFromConfig(*config),
		ssm: ssm.NewFromConfig(*config),
	}

	return nil
}

func (m *mutator) createAWSConfig(ctx context.Context, k8sClient kubernetes.Interface) (*aws.Config, error) {
	common.AuthAttempts.WithLabelValues("aws").Inc()

	httpClient := cleanhttp.DefaultPooledClient()
	httpClient.Transport = common.InstrumentRoundTripper(httpClient.Transport, "aws")

	if m.config.LoadFromSecret {
		return m.createConfigUsingK8sSecretCredentials(ctx, k8sClient, httpClient)
	}

	config, err := config.LoadDefaultConfig(ctx, config.WithRegion(m.config.Region), config.WithHTTPClient(httpClient))
	if err != nil {
		common.AuthAttemptsErrors.WithLabelValues("aws", "config_error").Inc()
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	return &config, nil
}

func (m *mutator) createConfigUsingK8sSecretCredentials(ctx context.Context, k8sClient kubernetes.Interface, httpClient *http.Client) (*aws.Config, error) {
	secret, err := m.getK8sSecretCredentials(ctx, k8sClient)
	if err != nil {
		common.AuthAttemptsErrors.WithLabelValues("aws", "kubernetes_error").Inc()
		return nil, fmt.Errorf("failed to get AWS credentials from Kubernetes secret: %w", err)
	}

	awsAccessKeyID, ok := secret["aws_access_key_id"]
	if !ok {
		common.AuthAttemptsErrors.WithLabelValues("aws", "kubernetes_error").Inc()
		return nil, fmt.Errorf("AWS access key ID not found in Kubernetes secret")
	}
	awsSecretAccessKey, ok := secret["aws_secret_access_key"]
	if !ok {
		common.AuthAttemptsErrors.WithLabelValues("aws", "kubernetes_error").Inc()
		return nil, fmt.Errorf("AWS secret access key not found in Kubernetes secret")
	}
	sessionToken, ok := secret["aws_session_token"]
	if !ok {
		sessionToken = []byte("")
	}

	config, err := config.LoadDefaultConfig(ctx,
		config.WithRegion(m.config.Region),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(
			string(awsAccessKeyID),
			string(awsSecretAccessKey),
			string(sessionToken),
		)),
		config.WithHTTPClient(httpClient),
	)
	if err != nil {
		common.AuthAttemptsErrors.WithLabelValues("aws", "kubernetes_error").Inc()
		return nil, fmt.Errorf("failed to load AWS config with Kubernetes credentials: %w", err)
	}

	return &config, nil
}

func (m *mutator) getK8sSecretCredentials(ctx context.Context, k8sClient kubernetes.Interface) (map[string][]byte, error) {
	secret, err := k8sClient.CoreV1().Secrets(m.config.CredentialsNamespace).Get(
		ctx,
		m.config.CredentialsSecretName,
		metav1.GetOptions{},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to get AWS credentials secret: %w", err)
	}

	return secret.Data, nil
}
