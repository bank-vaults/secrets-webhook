package common

import (
	"testing"

	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestLoadConfig(t *testing.T) {
	tests := []struct {
		name        string
		annotations map[string]string
		want        map[string]string
	}{
		{
			name: "Handle deprecated annotations all",
			annotations: map[string]string{
				MutateAnnotationDeprecated:                      "true",
				PSPAllowPrivilegeEscalationAnnotationDeprecated: "true",
				RunAsNonRootAnnotationDeprecated:                "true",
				RunAsUserAnnotationDeprecated:                   "1000",
				RunAsGroupAnnotationDeprecated:                  "1000",
				ReadOnlyRootFsAnnotationDeprecated:              "true",
				RegistrySkipVerifyAnnotationDeprecated:          "true",
				MutateProbesAnnotationDeprecated:                "true",
				VaultEnvDaemonAnnotationDeprecated:              "true",
				VaultEnvDelayAnnotationDeprecated:               "10s",
				VaultEnvEnableJSONLogAnnotationDeprecated:       "true",
				VaultEnvImageAnnotationDeprecated:               "vault:latest",
				VaultEnvImagePullPolicyAnnotationDeprecated:     "Always",
			},
			want: map[string]string{
				MutateAnnotation:                      "true",
				PSPAllowPrivilegeEscalationAnnotation: "true",
				RunAsNonRootAnnotation:                "true",
				RunAsUserAnnotation:                   "1000",
				RunAsGroupAnnotation:                  "1000",
				ReadOnlyRootFsAnnotation:              "true",
				RegistrySkipVerifyAnnotation:          "true",
				MutateProbesAnnotation:                "true",
				SecretInitDaemonAnnotation:            "true",
				SecretInitDelayAnnotation:             "10s",
				SecretInitJSONLogAnnotation:           "true",
				SecretInitImageAnnotation:             "vault:latest",
				SecretInitImagePullPolicyAnnotation:   "Always",
			},
		},
		{
			name: "Handle deprecated annotations mixed",
			annotations: map[string]string{
				MutateAnnotationDeprecated:                      "true",
				PSPAllowPrivilegeEscalationAnnotationDeprecated: "true",
				RunAsGroupAnnotation:                            "1000",
				RegistrySkipVerifyAnnotationDeprecated:          "true",
				MutateProbesAnnotation:                          "true",
			},
			want: map[string]string{
				MutateAnnotation:                      "true",
				PSPAllowPrivilegeEscalationAnnotation: "true",
				RunAsGroupAnnotation:                  "1000",
				RegistrySkipVerifyAnnotation:          "true",
				MutateProbesAnnotation:                "true",
			},
		},
		{
			name: "Should stop parsing annotations if mutate is set to skip",
			annotations: map[string]string{
				MutateAnnotationDeprecated:                      "skip",
				PSPAllowPrivilegeEscalationAnnotationDeprecated: "true",
				RunAsGroupAnnotation:                            "1000",
				RegistrySkipVerifyAnnotationDeprecated:          "true",
			},
			want: map[string]string{
				MutateAnnotation: "skip",
			},
		},
	}

	for _, tt := range tests {
		ttp := tt
		t.Run(ttp.name, func(t *testing.T) {
			whConfigWant := LoadWebhookConfig(&metav1.ObjectMeta{Annotations: ttp.want})
			whConfigGot := LoadWebhookConfig(&metav1.ObjectMeta{Annotations: ttp.annotations})

			assert.Equal(t, whConfigWant, whConfigGot)

			secretInitConfigWant := LoadSecretInitConfig(&metav1.ObjectMeta{Annotations: ttp.want})
			secretInitConfigGot := LoadSecretInitConfig(&metav1.ObjectMeta{Annotations: ttp.annotations})

			assert.Equal(t, secretInitConfigWant, secretInitConfigGot)

		})
	}
}
