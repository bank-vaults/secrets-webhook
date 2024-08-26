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

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
	"github.com/aws/aws-sdk-go/service/ssm"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

type mutator struct {
	client *client
	config *Config
	logger *slog.Logger
}

type client struct {
	smClient  *secretsmanager.SecretsManager
	ssmClient *ssm.SSM
}

func (m *mutator) newClient(ctx context.Context, k8sClient kubernetes.Interface) error {
	sess, err := m.createAWSSession(ctx, k8sClient)
	if err != nil {
		return fmt.Errorf("failed to create AWS session: %w", err)
	}

	m.client = &client{
		smClient:  secretsmanager.New(sess),
		ssmClient: ssm.New(sess),
	}

	return nil
}

func (m *mutator) createAWSSession(ctx context.Context, k8sClient kubernetes.Interface) (*session.Session, error) {
	// Loading session data from shared config is disabled by default and needs to be
	// explicitly enabled via AWS_LOAD_FROM_SHARED_CONFIG
	options := session.Options{
		SharedConfigState: session.SharedConfigDisable,
		Config: aws.Config{
			Region: aws.String(m.config.Region),
		},
	}

	// Enable loading session data from mounted .aws directory
	if m.config.LoadFromSharedConfig {
		options.SharedConfigState = session.SharedConfigEnable
	} else {
		// Create session using Kubernetes secret credentials
		var err error
		options, err = m.createSessionUsingK8sSecretCredentials(ctx, k8sClient)
		if err != nil {
			return nil, fmt.Errorf("failed to create session using Kubernetes secret credentials: %w", err)
		}
	}

	// Create session
	sess, err := session.NewSessionWithOptions(options)
	if err != nil {
		return nil, fmt.Errorf("failed to create AWS session: %w", err)
	}

	return sess, nil
}

func (m *mutator) createSessionUsingK8sSecretCredentials(ctx context.Context, k8sClient kubernetes.Interface) (session.Options, error) {
	secret, err := m.getK8sSecretCredentials(ctx, k8sClient)
	if err != nil {
		return session.Options{}, fmt.Errorf("failed to get Kubernetes secret credentials: %w", err)
	}

	return session.Options{
		SharedConfigState: session.SharedConfigDisable,
		Config: aws.Config{
			Region:      aws.String(m.config.Region),
			Credentials: credentials.NewStaticCredentials(string(secret["AWS_ACCESS_KEY_ID"]), string(secret["AWS_SECRET_ACCESS_KEY"]), ""),
		},
	}, nil
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
