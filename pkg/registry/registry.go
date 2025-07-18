// Copyright © 2021 Banzai Cloud
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

package registry

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"slices"

	"emperror.dev/errors"
	"github.com/google/go-containerregistry/pkg/authn/k8schain"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/patrickmn/go-cache"
	slogmulti "github.com/samber/slog-multi"
	"github.com/spf13/viper"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
)

var logger *slog.Logger

func init() {
	router := slogmulti.Router()

	levelFilter := func(levels ...slog.Level) func(ctx context.Context, r slog.Record) bool {
		return func(_ context.Context, r slog.Record) bool {
			return slices.Contains(levels, r.Level)
		}
	}

	if viper.GetBool("enable_json_log") {
		// Send logs with level higher than warning to stderr
		router = router.Add(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))

		// Send info and debug logs to stdout
		router = router.Add(
			slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}),
			levelFilter(slog.LevelDebug, slog.LevelInfo),
		)
	} else {
		// Send logs with level higher than warning to stderr
		router = router.Add(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))

		// Send info and debug logs to stdout
		router = router.Add(
			slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}),
			levelFilter(slog.LevelDebug, slog.LevelInfo),
		)
	}

	// TODO: add level filter handler
	logger = slog.New(router.Handler())

	slog.SetDefault(logger)
}

// ImageRegistry is a docker registry
type ImageRegistry interface {
	GetImageConfig(
		ctx context.Context,
		clientset kubernetes.Interface,
		namespace string,
		isDisabled bool,
		container *corev1.Container,
		podSpec *corev1.PodSpec) (*v1.Config, error)
}

// Registry impl
type Registry struct {
	imageCache *cache.Cache
}

// NewRegistry creates and initializes registry
func NewRegistry() ImageRegistry {
	return &Registry{
		imageCache: cache.New(cache.NoExpiration, cache.NoExpiration),
	}
}

// IsAllowedToCache checks that information about Docker image can be cached
// base on image name and container PullPolicy
func IsAllowedToCache(container *corev1.Container) bool {
	if container.ImagePullPolicy == corev1.PullAlways {
		return false
	}

	reference, err := name.ParseReference(container.Image)
	if err != nil {
		return false
	}

	return reference.Identifier() != "latest"
}

// GetImageConfig returns entrypoint and command of container
func (r *Registry) GetImageConfig(
	ctx context.Context,
	client kubernetes.Interface,
	namespace string,
	isDisabled bool,
	container *corev1.Container,
	podSpec *corev1.PodSpec,
) (*v1.Config, error) {
	allowToCache := IsAllowedToCache(container)
	if allowToCache {
		if imageConfig, cacheHit := r.imageCache.Get(container.Image); cacheHit {
			logger.Info(fmt.Sprintf("found image %s in cache", container.Image))

			return imageConfig.(*v1.Config), nil
		}
	}

	containerInfo := containerInfo{
		Namespace:          namespace,
		ServiceAccountName: podSpec.ServiceAccountName,
		Image:              container.Image,
	}
	for _, imagePullSecret := range podSpec.ImagePullSecrets {
		containerInfo.ImagePullSecrets = append(containerInfo.ImagePullSecrets, imagePullSecret.Name)
	}

	// The pod imagePullSecrets did not contain any credentials.
	// Try to find matching registry credentials in the default imagePullSecret if one was provided.
	// Otherwise, cloud credential providers will be tried.
	defaultImagePullSecretNamespace := viper.GetString("default_image_pull_secret_namespace")
	defaultImagePullSecretServiceAccount := viper.GetString("default_image_pull_secret_service_account")
	defaultImagePullSecret := viper.GetString("default_image_pull_secret")
	if len(containerInfo.ImagePullSecrets) == 0 &&
		defaultImagePullSecretNamespace != "" && defaultImagePullSecret != "" && defaultImagePullSecretServiceAccount != "" {
		containerInfo.Namespace = defaultImagePullSecretNamespace
		containerInfo.ServiceAccountName = defaultImagePullSecretServiceAccount
		containerInfo.ImagePullSecrets = []string{defaultImagePullSecret}
	}

	imageConfig, err := getImageConfig(ctx, client, containerInfo, isDisabled)
	if imageConfig != nil && allowToCache {
		r.imageCache.Set(container.Image, imageConfig, cache.DefaultExpiration)
	}

	return imageConfig, err
}

// getImageConfig download image blob from registry
func getImageConfig(ctx context.Context, client kubernetes.Interface, container containerInfo, isDisabled bool) (*v1.Config, error) {
	registrySkipVerify := isDisabled

	chainOpts := k8schain.Options{
		Namespace:          container.Namespace,
		ServiceAccountName: container.ServiceAccountName,
		ImagePullSecrets:   container.ImagePullSecrets,
	}

	authChain, err := k8schain.New(
		ctx,
		client,
		chainOpts,
	)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to create k8schain authentication, opts: %+v", chainOpts)
	}

	options := []remote.Option{
		remote.WithAuthFromKeychain(authChain),
		remote.WithContext(ctx),
	}

	if registrySkipVerify {
		tr := remote.DefaultTransport.(*http.Transport).Clone()
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec
		options = append(options, remote.WithTransport(tr))
	}

	ref, err := name.ParseReference(container.Image)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse image reference")
	}

	descriptor, err := remote.Get(ref, options...)
	if err != nil {
		return nil, errors.Wrap(err, "cannot fetch image descriptor")
	}

	var image v1.Image
	if descriptor.MediaType.IsIndex() {
		index, err := descriptor.ImageIndex()
		if err != nil {
			return nil, errors.Wrap(err, "cannot get image index")
		}

		manifest, err := index.IndexManifest()
		if err != nil {
			return nil, errors.Wrap(err, "cannot get index manifest")
		}

		if len(manifest.Manifests) == 0 {
			return nil, errors.New("no manifests found in the image index")
		}

		// Get the first available image
		image, err = index.Image(manifest.Manifests[0].Digest)
		if err != nil {
			return nil, errors.Wrap(err, "cannot get image from manifest")
		}
	} else {
		image, err = descriptor.Image()
		if err != nil {
			return nil, errors.Wrap(err, "cannot convert image descriptor to v1.Image")
		}
	}

	configFile, err := image.ConfigFile()
	if err != nil {
		return nil, errors.Wrap(err, "cannot extract config file of image")
	}

	return &configFile.Config, nil
}

// containerInfo keeps information retrieved from POD based container definition
type containerInfo struct {
	Namespace          string
	ImagePullSecrets   []string
	ServiceAccountName string
	Image              string
}
