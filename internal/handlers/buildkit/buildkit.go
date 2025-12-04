package buildkit

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	sbomscannerv1alpha1 "github.com/kubewarden/sbomscanner/api/storage/v1alpha1"
	apiv1alpha1 "github.com/seatgeek/buildkit-operator/api/v1alpha1"
)

const BuildKitImage = "moby/buildkit:v0.25.1"

type BuildKitHandler struct {
	client.Client
	Scheme *runtime.Scheme
}

func NewBuildKitHandler(client client.Client, scheme *runtime.Scheme) *BuildKitHandler {
	return &BuildKitHandler{Client: client, Scheme: scheme}
}

func (h *BuildKitHandler) PrepareBuildKit(ctx context.Context, vr sbomscannerv1alpha1.VulnerabilityReport) error {
	name := vr.ImageMetadata.Registry
	namespace := vr.Namespace

	if err := h.ensureBuildkitTemplate(ctx, name, namespace, vr.ImageMetadata.RegistryURI); err != nil {
		return fmt.Errorf("failed to ensure BuildkitTemplate: %w", err)
	}

	if err := h.ensureBuildkit(ctx, name, namespace); err != nil {
		return fmt.Errorf("failed to ensure Buildkit: %w", err)
	}

	if err := h.ensureService(ctx, name, namespace); err != nil {
		return fmt.Errorf("failed to ensure Service: %w", err)
	}

	return nil
}

func (h *BuildKitHandler) ensureBuildkitTemplate(ctx context.Context, name, namespace, registryURI string) error {
	var existing apiv1alpha1.BuildkitTemplate
	err := h.Get(ctx, types.NamespacedName{Name: name, Namespace: namespace}, &existing)
	if err == nil {
		// 已存在，跳過
		return nil
	}
	if !apierrors.IsNotFound(err) {
		// 其他錯誤
		return err
	}

	// NotFound，建立新的
	template := &apiv1alpha1.BuildkitTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: apiv1alpha1.BuildkitTemplateSpec{
			Port:  1234,
			Image: BuildKitImage,
			BuildkitdToml: `debug = true
[registry."` + registryURI + `"]
http = true`,
			Resources: apiv1alpha1.BuildkitTemplateResources{
				Default: corev1.ResourceRequirements{
					Requests: corev1.ResourceList{
						corev1.ResourceMemory: resource.MustParse("2Gi"),
						corev1.ResourceCPU:    resource.MustParse("1000m"),
					},
					Limits: corev1.ResourceList{
						corev1.ResourceMemory: resource.MustParse("6Gi"),
						corev1.ResourceCPU:    resource.MustParse("4000m"),
					},
				},
			},
		},
	}
	return h.Create(ctx, template)
}

func (h *BuildKitHandler) ensureBuildkit(ctx context.Context, name, namespace string) error {
	var existing apiv1alpha1.Buildkit
	err := h.Get(ctx, types.NamespacedName{Name: name, Namespace: namespace}, &existing)
	if err == nil {
		return nil
	}
	if !apierrors.IsNotFound(err) {
		return err
	}

	buildkit := &apiv1alpha1.Buildkit{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: apiv1alpha1.BuildkitSpec{
			Template: name,
			Labels: map[string]string{
				"buildkit.seatgeek.io/name": name,
			},
			Resources: corev1.ResourceRequirements{
				Requests: corev1.ResourceList{
					corev1.ResourceMemory: resource.MustParse("2Gi"),
					corev1.ResourceCPU:    resource.MustParse("1000m"),
				},
				Limits: corev1.ResourceList{
					corev1.ResourceMemory: resource.MustParse("6Gi"),
					corev1.ResourceCPU:    resource.MustParse("4000m"),
				},
			},
		},
	}
	return h.Create(ctx, buildkit)
}

func (h *BuildKitHandler) ensureService(ctx context.Context, name, namespace string) error {
	var existing corev1.Service
	err := h.Get(ctx, types.NamespacedName{Name: name, Namespace: namespace}, &existing)
	if err == nil {
		return nil
	}
	if !apierrors.IsNotFound(err) {
		return err
	}

	service := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: corev1.ServiceSpec{
			Selector: map[string]string{
				"buildkit.seatgeek.io/name": name,
			},
			Ports: []corev1.ServicePort{
				{
					Port:       1234,
					TargetPort: intstr.FromInt32(1234),
					Protocol:   corev1.ProtocolTCP,
				},
			},
		},
	}
	return h.Create(ctx, service)
}
