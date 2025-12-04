/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controller

import (
	"context"
	"strings"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	sbomscannerv1alpha1 "github.com/kubewarden/sbomscanner/api/storage/v1alpha1"

	vulpatcherkubewardeniov1alpha1 "github.com/pohanhuangtw/vuln-patcher/api/v1alpha1"
	"github.com/pohanhuangtw/vuln-patcher/internal/handlers"
	"github.com/pohanhuangtw/vuln-patcher/internal/handlers/buildkit"
)

// PatchJobReconciler reconciles a PatchJob object
type PatchJobReconciler struct {
	client.Client
	Scheme                 *runtime.Scheme
	PatchContainersHandler *handlers.PatchContainersHandler
	BuildKitHandler        *buildkit.BuildKitHandler
}

func (r *PatchJobReconciler) filterPatchJob(sbomScannerReport sbomscannerv1alpha1.VulnerabilityReport) bool {
	return strings.Contains(sbomScannerReport.ImageMetadata.Tag, handlers.PatchTagSuffix)
}

// +kubebuilder:rbac:groups=vulpatcher.kubewarden.io,resources=patchjobs,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=vulpatcher.kubewarden.io,resources=patchjobs/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=vulpatcher.kubewarden.io,resources=patchjobs/finalizers,verbs=update
// +kubebuilder:rbac:groups=storage.sbomscanner.kubewarden.io,resources=vulnerabilityreports,verbs=get;list;watch

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the PatchJob object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.22.4/pkg/reconcile
func (r *PatchJobReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)
	log.Info("reconciling PatchJob", "namespacedName", req.NamespacedName)

	var vr sbomscannerv1alpha1.VulnerabilityReport
	if err := r.Get(ctx, req.NamespacedName, &vr); err != nil {
		if apierrors.IsNotFound(err) {
			log.Info("no VulnerabilityReport found for PatchJob",
				"patchJob", req.NamespacedName)
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	if r.filterPatchJob(vr) {
		log.Info("PatchJob is not applicable, skipping", "namespacedName", req.NamespacedName, "imageMetadata", vr.ImageMetadata)
		return ctrl.Result{}, nil
	}

	log.Info("PatchJob is applicable, patching containers", "namespacedName", req.NamespacedName, "imageMetadata", vr.ImageMetadata)
	var pj vulpatcherkubewardeniov1alpha1.PatchJob
	if err := r.Get(ctx, req.NamespacedName, &pj); err != nil {
		if apierrors.IsNotFound(err) {
			err := r.BuildKitHandler.PrepareBuildKit(ctx, vr)
			log.Info("BuildKit prepared, patching containers", "namespacedName", req.NamespacedName, "imageMetadata", vr.ImageMetadata, "error", err)
			if err != nil {
				log.Error(err, "error ensuring buildkit deployment")
				return ctrl.Result{}, err
			}

			err = r.PatchContainersHandler.Handle(ctx, vr)
			if err != nil {
				log.Error(err, "error patching containers")
				return ctrl.Result{}, err
			}

			pj = vulpatcherkubewardeniov1alpha1.PatchJob{
				ObjectMeta: metav1.ObjectMeta{
					Name:      req.NamespacedName.Name,
					Namespace: vr.Namespace,
				},
			}
			err = r.Create(ctx, &pj)
			if err != nil {
				log.Error(err, "error creating patch job")
				return ctrl.Result{}, err
			}
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	log.Info("found VulnerabilityReport for PatchJob",
		"patchJob", req.NamespacedName,
		"vrNamespace", vr.Namespace,
		"vrName", vr.Name,
		"req.NamespacedName", req.NamespacedName,
	)

	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *PatchJobReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&vulpatcherkubewardeniov1alpha1.PatchJob{}).
		Watches(
			&sbomscannerv1alpha1.VulnerabilityReport{},
			handler.EnqueueRequestsFromMapFunc(r.mapVRToPatchJob),
		).
		Named("patchjob").
		Complete(r)
}

// mapVRToPatchJob enqueues the PatchJob reconcile request for a VulnerabilityReport event.
// We treat PatchJobs as a 1:1 companion resource to VulnerabilityReports, and they share the same name/namespace.
func (r *PatchJobReconciler) mapVRToPatchJob(ctx context.Context, obj client.Object) []reconcile.Request {
	vr, ok := obj.(*sbomscannerv1alpha1.VulnerabilityReport)
	if !ok {
		logf.FromContext(ctx).V(1).Info("received non VulnerabilityReport event, skipping")
		return nil
	}

	return []reconcile.Request{{
		NamespacedName: client.ObjectKeyFromObject(vr),
	}}
}
