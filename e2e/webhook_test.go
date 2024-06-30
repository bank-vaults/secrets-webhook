// Copyright © 2023 Bank-Vaults Maintainers
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

//go:build e2e
// +build e2e

package e2e

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/e2e-framework/klient/decoder"
	"sigs.k8s.io/e2e-framework/klient/k8s/resources"
	"sigs.k8s.io/e2e-framework/klient/wait"
	"sigs.k8s.io/e2e-framework/klient/wait/conditions"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
	"sigs.k8s.io/e2e-framework/pkg/features"
)

func TestSecretValueInjection(t *testing.T) {
	secretVault := applyResource(features.New("secret-vault"), "secret-vault.yaml").
		Assess("object created", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			secrets := &v1.SecretList{
				Items: []v1.Secret{
					{
						ObjectMeta: metav1.ObjectMeta{Name: "test-secret-vault", Namespace: cfg.Namespace()},
					},
				},
			}

			// wait for the secret to become available
			err := wait.For(conditions.New(cfg.Client().Resources()).ResourcesFound(secrets), wait.WithTimeout(defaultTimeout))
			require.NoError(t, err)

			return ctx
		}).
		Assess("secret values are injected", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			var secret v1.Secret

			err := cfg.Client().Resources(cfg.Namespace()).Get(ctx, "test-secret-vault", cfg.Namespace(), &secret)
			require.NoError(t, err)

			type v1 struct {
				Username string `json:"username"`
				Password string `json:"password"`
				Auth     string `json:"auth"`
			}

			type auths struct {
				V1 v1 `json:"https://index.docker.io/v1/"`
			}

			type dockerconfig struct {
				Auths auths `json:"auths"`
			}

			var dockerconfigjson dockerconfig

			err = json.Unmarshal(secret.Data[".dockerconfigjson"], &dockerconfigjson)
			require.NoError(t, err)

			assert.Equal(t, "dockerrepouser", dockerconfigjson.Auths.V1.Username)
			assert.Equal(t, "dockerrepopassword", dockerconfigjson.Auths.V1.Password)
			assert.Equal(t, "Inline: secretId AWS_ACCESS_KEY_ID", string(secret.Data["inline"]))

			return ctx
		}).
		Feature()

	configMapVault := applyResource(features.New("configmap-vault"), "configmap-vault.yaml").
		Assess("object created", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			configMaps := &v1.ConfigMapList{
				Items: []v1.ConfigMap{
					{
						ObjectMeta: metav1.ObjectMeta{Name: "test-configmap-vault", Namespace: cfg.Namespace()},
					},
				},
			}

			// wait for the secret to become available
			err := wait.For(conditions.New(cfg.Client().Resources()).ResourcesFound(configMaps), wait.WithTimeout(defaultTimeout))
			require.NoError(t, err)

			return ctx
		}).
		Assess("secret values are injected", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			var configMap v1.ConfigMap

			err := cfg.Client().Resources(cfg.Namespace()).Get(ctx, "test-configmap-vault", cfg.Namespace(), &configMap)
			require.NoError(t, err)

			assert.Equal(t, "secretId", string(configMap.Data["aws-access-key-id"]))
			assert.Equal(t, "AWS key in base64: c2VjcmV0SWQ=", string(configMap.Data["aws-access-key-id-formatted"]))
			assert.Equal(t, "AWS_ACCESS_KEY_ID: secretId AWS_SECRET_ACCESS_KEY: s3cr3t", string(configMap.Data["aws-access-key-id-inline"]))
			assert.Equal(t, "secretId", base64.StdEncoding.EncodeToString(configMap.BinaryData["aws-access-key-id-binary"]))

			return ctx
		}).
		Feature()

	testenv.Test(t, secretVault, configMapVault)
}

func TestPodMutation(t *testing.T) {
	deploymentVault := applyResource(features.New("deployment-vault"), "deployment-vault.yaml").
		Assess("available", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			deployment := &appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{Name: "test-deployment-vault", Namespace: cfg.Namespace()},
			}

			// wait for the deployment to become available
			err := wait.For(conditions.New(cfg.Client().Resources()).DeploymentConditionMatch(deployment, appsv1.DeploymentAvailable, v1.ConditionTrue), wait.WithTimeout(defaultTimeout))
			require.NoError(t, err)

			return ctx
		}).
		Assess("security context defaults are correct", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			r := cfg.Client().Resources()
			pods := &v1.PodList{}

			err := r.List(ctx, pods, resources.WithLabelSelector("app.kubernetes.io/name=test-deployment-vault"))
			require.NoError(t, err)

			assert.NotEmpty(t, pods.Items, "no pods found")

			securityContext := pods.Items[0].Spec.InitContainers[0].SecurityContext
			assert.Nil(t, securityContext.RunAsNonRoot)
			assert.Nil(t, securityContext.RunAsUser)
			assert.Nil(t, securityContext.RunAsGroup)

			return ctx
		}).
		Assess("secret values are injected", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			r := cfg.Client().Resources()
			pods := &v1.PodList{}

			err := r.List(ctx, pods, resources.WithLabelSelector("app.kubernetes.io/name=test-deployment-vault"))
			require.NoError(t, err)

			assert.NotEmpty(t, pods.Items, "no pods found")

			// wait for the container to become available
			err = wait.For(conditions.New(r).ContainersReady(&pods.Items[0]), wait.WithTimeout(defaultTimeout))
			require.NoError(t, err)

			initContainerLogs := getLogsFromContainer(t, ctx, cfg, pods.Items[0].Name, pods.Items[0].Spec.InitContainers[1].Name)
			assert.Contains(t, initContainerLogs, "AWS_SECRET_ACCESS_KEY=s3cr3t")

			containerLogs := getLogsFromContainer(t, ctx, cfg, pods.Items[0].Name, pods.Items[0].Spec.Containers[0].Name)
			assert.Contains(t, containerLogs, "AWS_SECRET_ACCESS_KEY=s3cr3t")

			return ctx
		}).
		Feature()

	deploymentSeccontextVault := applyResource(features.New("deployment-seccontext-vault"), "deployment-seccontext-vault.yaml").
		Assess("available", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			deployment := &appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{Name: "test-deployment-seccontext-vault", Namespace: cfg.Namespace()},
			}

			// wait for the deployment to become available
			err := wait.For(conditions.New(cfg.Client().Resources()).DeploymentConditionMatch(deployment, appsv1.DeploymentAvailable, v1.ConditionTrue), wait.WithTimeout(defaultTimeout))
			require.NoError(t, err)

			return ctx
		}).
		Assess("secret values are injected", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			r := cfg.Client().Resources()
			pods := &v1.PodList{}

			err := r.List(ctx, pods, resources.WithLabelSelector("app.kubernetes.io/name=test-deployment-vault"))
			require.NoError(t, err)

			assert.NotEmpty(t, pods.Items, "no pods found")

			// wait for the container to become available
			err = wait.For(conditions.New(r).ContainersReady(&pods.Items[0]), wait.WithTimeout(defaultTimeout))
			require.NoError(t, err)

			initContainerLogs := getLogsFromContainer(t, ctx, cfg, pods.Items[0].Name, pods.Items[0].Spec.InitContainers[1].Name)
			assert.Contains(t, initContainerLogs, "AWS_SECRET_ACCESS_KEY=s3cr3t")

			containerLogs := getLogsFromContainer(t, ctx, cfg, pods.Items[0].Name, pods.Items[0].Spec.Containers[0].Name)
			assert.Contains(t, containerLogs, "AWS_SECRET_ACCESS_KEY=s3cr3t")

			return ctx
		}).
		Feature()

	deploymentTemplatingVault := applyResource(features.New("deployment-template-vault"), "deployment-template-vault.yaml").
		Assess("available", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			r := cfg.Client().Resources()

			deployment := &appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{Name: "test-deployment-template-vault", Namespace: cfg.Namespace()},
			}

			// wait for the deployment to become available
			err := wait.For(conditions.New(r).DeploymentConditionMatch(deployment, appsv1.DeploymentAvailable, v1.ConditionTrue), wait.WithTimeout(defaultTimeout))
			require.NoError(t, err)

			return ctx
		}).
		Assess("config template", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			r := cfg.Client().Resources()
			pods := &v1.PodList{}

			err := r.List(ctx, pods, resources.WithLabelSelector("app.kubernetes.io/name=test-deployment-template-vault"))
			require.NoError(t, err)

			assert.NotEmpty(t, pods.Items, "no pods found")

			// wait for the container to become available
			err = wait.For(conditions.New(r).ContainersReady(&pods.Items[0]), wait.WithTimeout(defaultTimeout))
			require.NoError(t, err)

			var stdout, stderr bytes.Buffer
			command := []string{"cat", "/vault/secrets/config.yaml"}
			if err := r.ExecInPod(ctx, cfg.Namespace(), pods.Items[0].Name, pods.Items[0].Spec.Containers[0].Name, command, &stdout, &stderr); err != nil {
				t.Log(stderr.String())
				t.Fatal(err)
			}
			assert.Equal(t, "\n    {\n      \"id\": \"secretId\",\n      \"key\": \"s3cr3t\"\n    }\n    \n  ", stdout.String())

			return ctx
		}).
		Feature()

	deploymentInitSeccontextVault := applyResource(features.New("deployment-init-seccontext-vault"), "deployment-init-seccontext-vault.yaml").
		Assess("available", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			deployment := &appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{Name: "test-deployment-init-seccontext-vault", Namespace: cfg.Namespace()},
			}

			// wait for the deployment to become available
			err := wait.For(conditions.New(cfg.Client().Resources()).DeploymentConditionMatch(deployment, appsv1.DeploymentAvailable, v1.ConditionTrue), wait.WithTimeout(defaultTimeout))
			require.NoError(t, err)

			return ctx
		}).
		Assess("security context is correct", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			r := cfg.Client().Resources()
			pods := &v1.PodList{}

			err := r.List(ctx, pods, resources.WithLabelSelector("app.kubernetes.io/name=test-deployment-init-seccontext-vault"))
			require.NoError(t, err)

			assert.NotEmpty(t, pods.Items, "no pods found")

			// wait for the container to become available
			err = wait.For(conditions.New(r).ContainersReady(&pods.Items[0]), wait.WithTimeout(defaultTimeout))
			require.NoError(t, err)

			securityContext := pods.Items[0].Spec.InitContainers[0].SecurityContext
			require.NotNil(t, securityContext.RunAsNonRoot)
			assert.Equal(t, true, *securityContext.RunAsNonRoot)
			require.NotNil(t, securityContext.RunAsUser)
			assert.Equal(t, int64(1000), *securityContext.RunAsUser)
			require.NotNil(t, securityContext.RunAsGroup)
			assert.Equal(t, int64(1000), *securityContext.RunAsGroup)

			return ctx
		}).
		Assess("secret value is injected", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			r := cfg.Client().Resources()
			pods := &v1.PodList{}

			err := r.List(ctx, pods, resources.WithLabelSelector("app.kubernetes.io/name=test-deployment-init-seccontext-vault"))
			require.NoError(t, err)

			assert.NotEmpty(t, pods.Items, "no pods found")

			// wait for the container to become available
			err = wait.For(conditions.New(r).ContainersReady(&pods.Items[0]), wait.WithTimeout(defaultTimeout))
			require.NoError(t, err)

			containerLogs := getLogsFromContainer(t, ctx, cfg, pods.Items[0].Name, pods.Items[0].Spec.Containers[0].Name)
			assert.Contains(t, containerLogs, "AWS_SECRET_ACCESS_KEY=s3cr3t")

			return ctx
		}).
		Feature()

	testenv.Test(t, deploymentVault, deploymentSeccontextVault, deploymentTemplatingVault, deploymentInitSeccontextVault)
}

func applyResource(builder *features.FeatureBuilder, file string) *features.FeatureBuilder {
	return builder.
		Setup(func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			err := decoder.DecodeEachFile(
				ctx, os.DirFS("test"), file,
				decoder.CreateHandler(cfg.Client().Resources()),
				decoder.MutateNamespace(cfg.Namespace()),
			)
			require.NoError(t, err)

			return ctx
		}).
		Teardown(func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			err := decoder.DecodeEachFile(
				ctx, os.DirFS("test"), file,
				decoder.DeleteHandler(cfg.Client().Resources()),
				decoder.MutateNamespace(cfg.Namespace()),
			)
			require.NoError(t, err)

			return ctx
		})
}

func getLogsFromContainer(t *testing.T, ctx context.Context, cfg *envconf.Config, podName string, containerName string) string {
	clientset, err := kubernetes.NewForConfig(cfg.Client().RESTConfig())
	require.NoError(t, err)

	req := clientset.CoreV1().Pods(cfg.Namespace()).GetLogs(
		podName,
		&v1.PodLogOptions{
			Container: containerName,
		})

	podLogs, err := req.Stream(ctx)
	require.NoError(t, err)
	defer podLogs.Close()

	var buf bytes.Buffer
	_, err = buf.ReadFrom(podLogs)
	require.NoError(t, err)

	return buf.String()
}
