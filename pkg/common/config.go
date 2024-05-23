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
	"strconv"

	"github.com/spf13/viper"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Config represents the configuration for the webhook
type Config struct {
	PspAllowPrivilegeEscalation bool
	RunAsNonRoot                bool
	RunAsUser                   int64
	RunAsGroup                  int64
	ReadOnlyRootFilesystem      bool
	RegistrySkipVerify          bool
	Mutate                      bool
	MutateProbes                bool
	Provider                    string
}

func LoadWebhookConfig(obj metav1.Object) Config {
	config := Config{}

	annotations := obj.GetAnnotations()

	if val, ok := annotations[CleanupOldAnnotationsAnnotation]; ok {
		ok, _ := strconv.ParseBool(val)
		if ok {
			annotations = handleDeprecatedWebhookAnnotations(annotations)
		} else {
			annotations = handleDeprecatedWebhookAnnotationsWithoutDelete(annotations)
		}
	}

	if val := annotations[MutateAnnotation]; val == "skip" {
		config.Mutate = true

		return config
	}

	if val, ok := annotations[PSPAllowPrivilegeEscalationAnnotation]; ok {
		config.PspAllowPrivilegeEscalation, _ = strconv.ParseBool(val)
	} else {
		config.PspAllowPrivilegeEscalation, _ = strconv.ParseBool(viper.GetString(PSPAllowPrivilegeEscalationEnvVar))
	}

	if val, ok := annotations[RunAsNonRootAnnotation]; ok {
		config.RunAsNonRoot, _ = strconv.ParseBool(val)
	} else {
		config.RunAsNonRoot, _ = strconv.ParseBool(viper.GetString(RunAsNonRootEnvVar))
	}

	if val, ok := annotations[RunAsUserAnnotation]; ok {
		config.RunAsUser, _ = strconv.ParseInt(val, 10, 64)
	} else {
		config.RunAsUser, _ = strconv.ParseInt(viper.GetString(RunAsUserEnvVar), 0, 64)
	}

	if val, ok := annotations[RunAsGroupAnnotation]; ok {
		config.RunAsGroup, _ = strconv.ParseInt(val, 10, 64)
	} else {
		config.RunAsGroup, _ = strconv.ParseInt(viper.GetString(RunAsGroupEnvVar), 0, 64)
	}

	if val, ok := annotations[ReadOnlyRootFsAnnotation]; ok {
		config.ReadOnlyRootFilesystem, _ = strconv.ParseBool(val)
	} else {
		config.ReadOnlyRootFilesystem, _ = strconv.ParseBool(viper.GetString(ReadonlyRootFSEnvVar))
	}

	if val, ok := annotations[RegistrySkipVerifyAnnotation]; ok {
		config.RegistrySkipVerify, _ = strconv.ParseBool(val)
	} else {
		config.RegistrySkipVerify, _ = strconv.ParseBool(viper.GetString(RegistrySkipVerifyEnvVar))
	}

	if val, ok := annotations[MutateProbesAnnotation]; ok {
		config.MutateProbes, _ = strconv.ParseBool(val)
	}

	if val, ok := annotations[ProviderAnnotation]; ok {
		config.Provider = val
	}

	return config
}

func SetConfigDefaults() {
	viper.SetDefault(PSPAllowPrivilegeEscalationEnvVar, "false")
	viper.SetDefault(RunAsNonRootEnvVar, "false")
	viper.SetDefault(RunAsUserEnvVar, "0")
	viper.SetDefault(RunAsGroupEnvVar, "0")
	viper.SetDefault(ReadonlyRootFSEnvVar, "false")
	viper.SetDefault(RegistrySkipVerifyEnvVar, "false")
	viper.SetDefault(MutateConfigMapEnvVar, "false")
	viper.SetDefault(DefaultImagePullSecretEnvVar, "")
	viper.SetDefault(DefaultImagePullSecretSAEnvVar, "")
	viper.SetDefault(DefaultImagePullSecretNSEnvVar, "")
	viper.SetDefault(TLSCertFileEnvVar, "")
	viper.SetDefault(TLSPrivateKeyFileEnvVar, "")
	viper.SetDefault(ListenAddressEnvVar, ":8443")
	viper.SetDefault(TelemetryListenAddressEnvVar, "")

	viper.AutomaticEnv()
}

// This is implemented to preserve backwards compatibility with the deprecated annotations
func handleDeprecatedWebhookAnnotations(annotations map[string]string) map[string]string {

	if val, ok := annotations[MutateAnnotationDeprecated]; ok {
		annotations[MutateAnnotation] = val
		delete(annotations, MutateAnnotationDeprecated)

		// Do an early exit if the resource shouldn't be mutated
		if val == "skip" {
			return annotations
		}
	}

	if val, ok := annotations[PSPAllowPrivilegeEscalationAnnotationDeprecated]; ok {
		annotations[PSPAllowPrivilegeEscalationAnnotation] = val
		delete(annotations, PSPAllowPrivilegeEscalationAnnotationDeprecated)
	}

	if val, ok := annotations[RunAsNonRootAnnotationDeprecated]; ok {
		annotations[RunAsNonRootAnnotation] = val
		delete(annotations, RunAsNonRootAnnotationDeprecated)
	}

	if val, ok := annotations[RunAsUserAnnotationDeprecated]; ok {
		annotations[RunAsUserAnnotation] = val
		delete(annotations, RunAsUserAnnotationDeprecated)
	}

	if val, ok := annotations[RunAsGroupAnnotationDeprecated]; ok {
		annotations[RunAsGroupAnnotation] = val
		delete(annotations, RunAsGroupAnnotationDeprecated)
	}

	if val, ok := annotations[ReadOnlyRootFsAnnotationDeprecated]; ok {
		annotations[ReadOnlyRootFsAnnotation] = val
		delete(annotations, ReadOnlyRootFsAnnotationDeprecated)
	}

	if val, ok := annotations[RegistrySkipVerifyAnnotationDeprecated]; ok {
		annotations[RegistrySkipVerifyAnnotation] = val
		delete(annotations, RegistrySkipVerifyAnnotationDeprecated)
	}

	if val, ok := annotations[MutateProbesAnnotationDeprecated]; ok {
		annotations[MutateProbesAnnotation] = val
		delete(annotations, MutateProbesAnnotationDeprecated)
	}

	return annotations
}

// This is implemented to preserve backwards compatibility with the deprecated annotations
func handleDeprecatedWebhookAnnotationsWithoutDelete(annotations map[string]string) map[string]string {

	if val, ok := annotations[MutateAnnotationDeprecated]; ok {
		annotations[MutateAnnotation] = val

		// Do an early exit if the resource shouldn't be mutated
		if val == "skip" {
			return annotations
		}
	}

	if val, ok := annotations[PSPAllowPrivilegeEscalationAnnotationDeprecated]; ok {
		annotations[PSPAllowPrivilegeEscalationAnnotation] = val
	}

	if val, ok := annotations[RunAsNonRootAnnotationDeprecated]; ok {
		annotations[RunAsNonRootAnnotation] = val
	}

	if val, ok := annotations[RunAsUserAnnotationDeprecated]; ok {
		annotations[RunAsUserAnnotation] = val
	}

	if val, ok := annotations[RunAsGroupAnnotationDeprecated]; ok {
		annotations[RunAsGroupAnnotation] = val
	}

	if val, ok := annotations[ReadOnlyRootFsAnnotationDeprecated]; ok {
		annotations[ReadOnlyRootFsAnnotation] = val
	}

	if val, ok := annotations[RegistrySkipVerifyAnnotationDeprecated]; ok {
		annotations[RegistrySkipVerifyAnnotation] = val
	}

	if val, ok := annotations[MutateProbesAnnotationDeprecated]; ok {
		annotations[MutateProbesAnnotation] = val
	}

	return annotations
}
