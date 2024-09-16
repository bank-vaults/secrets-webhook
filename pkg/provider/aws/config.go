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
	"strconv"

	"github.com/spf13/viper"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/bank-vaults/secrets-webhook/pkg/common"
)

const (
	defaultCredentialsNamespace  = "default"
	defaultCredentialsSecretName = "aws-credentials"
)

type Config struct {
	ObjectNamespace       string
	Region                string
	LoadFromSharedConfig  bool
	CredentialsNamespace  string
	CredentialsSecretName string
	TLSSecretARN          string
}

func loadConfig(obj metav1.Object) *Config {
	config := Config{
		ObjectNamespace: obj.GetNamespace(),
	}

	annotations := obj.GetAnnotations()

	if val, ok := annotations[common.AWSRegionAnnotation]; ok {
		config.Region = val
	} else {
		config.Region = viper.GetString(common.AWSRegionEnvVar)
	}

	if val, ok := annotations[common.AWSLoadFromSharedConfigAnnotation]; ok {
		config.LoadFromSharedConfig, _ = strconv.ParseBool(val)
	} else {
		config.LoadFromSharedConfig = viper.GetBool(common.AWSLoadFromSharedConfigEnvVar)
	}

	if val, ok := annotations[common.AWSCredentialsNamespaceAnnotation]; ok {
		config.CredentialsNamespace = val
	} else if viper.IsSet(common.AWSCredentialsNamespaceEnvVar) {
		config.CredentialsNamespace = viper.GetString(common.AWSCredentialsNamespaceEnvVar)
	} else {
		config.CredentialsNamespace = defaultCredentialsNamespace
	}

	if val, ok := annotations[common.AWSCredentialsSecretNameAnnotation]; ok {
		config.CredentialsSecretName = val
	} else if viper.IsSet(common.AWSCredentialsSecretNameEnvVar) {
		config.CredentialsSecretName = viper.GetString(common.AWSCredentialsSecretNameEnvVar)
	} else {
		config.CredentialsSecretName = defaultCredentialsSecretName
	}

	if val, ok := annotations[common.AWSTLSSecretARNAnnotation]; ok {
		config.TLSSecretARN = val
	} else {
		config.TLSSecretARN = viper.GetString(common.AWSTLSSecretARNEnvVar)
	}

	return &config
}
