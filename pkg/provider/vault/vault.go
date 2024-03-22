package vault

import (
	"context"

	"github.com/bank-vaults/secrets-webhook/pkg/common"
	"github.com/bank-vaults/secrets-webhook/pkg/registry"
	"github.com/bank-vaults/vault-sdk/vault"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/kubernetes"
)

type Provider struct {
	Client    *vault.Client
	K8sClient kubernetes.Interface
	Registry  registry.ImageRegistry
	Config    Config
}

func NewProvider(client *vault.Client, k8sClient kubernetes.Interface, registry registry.ImageRegistry, config Config) *Provider {
	return &Provider{
		Client:    client,
		K8sClient: k8sClient,
		Registry:  registry,
		Config:    config,
	}
}

func (p *Provider) MutatePod(ctx context.Context, pod *corev1.Pod, appConfig common.AppConfig, secretInitConfig common.SecretInitConfig, dryRun bool) error {
	return podMutator(ctx, pod, appConfig, secretInitConfig, p.Config, p.K8sClient, p.Registry, dryRun)
}

func (p *Provider) MutateSecret(secret *corev1.Secret) error {
	return secretMutator(secret, p.Config, p.Client)
}

func (p *Provider) MutateConfigMap(configMap *corev1.ConfigMap) error {
	return configMapMutator(configMap, p.Config, p.Client)
}

func (p *Provider) MutateObject(obj *unstructured.Unstructured) error {
	return objectMutator(obj, p.Config, p.Client)
}
