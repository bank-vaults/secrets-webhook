package provider

import (
	"context"

	"github.com/bank-vaults/secrets-webhook/pkg/common"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

type Provider interface {
	MutatePod(ctx context.Context, pod *corev1.Pod, appConfig common.AppConfig, secretInitConfig common.SecretInitConfig, dryRun bool) error
	MutateSecret(secret *corev1.Secret) error
	MutateConfigMap(configMap *corev1.ConfigMap) error
	MutateObject(obj *unstructured.Unstructured) error
}
