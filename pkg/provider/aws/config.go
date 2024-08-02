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

type Config struct {
	ObjectNamespace      string
	Region               string
	LoadFromSharedConfig bool
}

func loadConfig(obj metav1.Object) (Config, error) {
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

	return config, nil
}
