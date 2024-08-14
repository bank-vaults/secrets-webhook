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
	"encoding/json"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
	"github.com/aws/aws-sdk-go/service/ssm"
)

func getDataFromStore(ctx context.Context, storeClient client, storeType string, data map[string]string) (map[string]string, error) {
	switch storeType {
	case "sm":
		return getDataFromSM(ctx, storeClient, data)
	case "ssm":
		return getDataFromSSM(ctx, storeClient, data)
	default:
		return nil, fmt.Errorf("unknown store type: %s", storeType)
	}
}

func getDataFromSM(ctx context.Context, storeClient client, data map[string]string) (map[string]string, error) {
	var secretsMap = make(map[string]string, len(data))
	for key, value := range data {
		if !strings.Contains(value, "secretsmanager:") {
			secretsMap[key] = value
			continue
		}

		secret, err := storeClient.smClient.GetSecretValueWithContext(
			ctx,
			&secretsmanager.GetSecretValueInput{
				SecretId: aws.String(value),
			})
		if err != nil {
			return nil, fmt.Errorf("failed to get secret from AWS secrets manager: %w", err)
		}

		secretBytes, err := extractSecretValueFromSM(secret)
		if err != nil {
			return nil, fmt.Errorf("failed to extract secret value from AWS secrets manager: %w", err)
		}

		secretValue, err := parseSecretValueFromSM(secretBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse secret value from AWS secrets manager: %w", err)
		}

		secretsMap[key] = string(secretValue)
	}

	return secretsMap, nil
}

// AWS Secrets Manager can store secrets in two formats:
// - SecretString: for text-based secrets, returned as a byte slice.
// - SecretBinary: for binary secrets, returned as a byte slice without additional encoding.
// If neither is available, the function returns an error.
//
// Ref: https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html
func extractSecretValueFromSM(secret *secretsmanager.GetSecretValueOutput) ([]byte, error) {
	// Secret available as string
	if secret.SecretString != nil {
		return []byte(aws.StringValue(secret.SecretString)), nil
	}

	// Secret available as binary
	if secret.SecretBinary != nil {
		return secret.SecretBinary, nil
	}

	// Handle the case where neither SecretString nor SecretBinary is available
	return []byte{}, fmt.Errorf("secret does not contain a value in expected formats")
}

// parseSecretValueFromSM takes a secret and attempts to parse it.
// It unifies the handling of all secrets coming from AWS SM,
// ensuring the output is consistent in the form of a []byte slice.
func parseSecretValueFromSM(secretBytes []byte) ([]byte, error) {
	// If the secret is not a JSON object, append it as a single secret
	if !json.Valid(secretBytes) {
		return secretBytes, nil
	}

	var secretValue map[string]interface{}
	err := json.Unmarshal(secretBytes, &secretValue)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal secret from AWS Secrets Manager: %w", err)
	}

	// If the JSON object contains a single key-value pair, the value is the actual secret
	if len(secretValue) == 1 {
		for _, value := range secretValue {
			return []byte(value.(string)), nil
		}
	}

	// For JSON objects with multiple key-value pairs, concatenate the values
	// into a single byte slice, separated by commas
	var concatenatedSecrets []byte
	for _, value := range secretValue {
		concatenatedSecrets = append(concatenatedSecrets, value.([]byte)...)
		concatenatedSecrets = append(concatenatedSecrets, ',')
	}

	return concatenatedSecrets, nil
}

func getDataFromSSM(ctx context.Context, storeClient client, data map[string]string) (map[string]string, error) {
	var secretsMap = make(map[string]string, len(data))
	for key, value := range data {
		if !strings.Contains(value, "ssm:") {
			secretsMap[key] = value
			continue
		}

		parameteredSecret, err := storeClient.ssmClient.GetParameterWithContext(
			ctx,
			&ssm.GetParameterInput{
				Name:           aws.String(value),
				WithDecryption: aws.Bool(true),
			})
		if err != nil {
			return nil, fmt.Errorf("failed to get secret from AWS SSM: %w", err)
		}

		secretsMap[key] = aws.StringValue(parameteredSecret.Parameter.Value)
	}

	return secretsMap, nil
}
func checkOtherStoreForSecrets(ctx context.Context, storeClient client, data map[string]string) (map[string]string, error) {
	// we might have ARN's that are from the other store type
	for k, v := range data {
		valid, storeType := isValidPrefixWithStoreType(v)
		if !valid {
			continue
		}

		secretFromOtherStore, err := getDataFromStore(ctx, storeClient, storeType, map[string]string{k: v})
		if err != nil {
			return nil, fmt.Errorf("getting data from store failed: %w", err)
		}

		for key, value := range secretFromOtherStore {
			data[key] = value
		}

	}

	return data, nil
}
