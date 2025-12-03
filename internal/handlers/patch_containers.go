package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"time"

	sbomscannerv1alpha1 "github.com/kubewarden/sbomscanner/api/storage/v1alpha1"

	"github.com/project-copacetic/copacetic/pkg/patch"
	"github.com/project-copacetic/copacetic/pkg/types"

	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type PatchContainersHandler struct {
	k8sClient             client.Client
	scheme                *runtime.Scheme
	workDir               string
	trivyJavaDBRepository string
	logger                *slog.Logger
}

func NewPatchContainersHandler(k8sClient client.Client, scheme *runtime.Scheme, workDir string, trivyJavaDBRepository string, logger *slog.Logger) *PatchContainersHandler {
	return &PatchContainersHandler{
		k8sClient:             k8sClient,
		scheme:                scheme,
		workDir:               workDir,
		trivyJavaDBRepository: trivyJavaDBRepository,
		logger:                logger,
	}
}

func (h *PatchContainersHandler) writeVulReportToTempFile(ctx context.Context, namespacedName client.ObjectKey) (string, error) {
	// 1. Get the VulnerabilityReport
	var vr sbomscannerv1alpha1.VulnerabilityReport
	if err := h.k8sClient.Get(ctx, namespacedName, &vr); err != nil {
		return "", err
	}

	// 1. Write the vul-report as temp file
	tempFile, err := os.CreateTemp(h.workDir, "vul-report-*.json")
	if err != nil {
		return "", err
	}
	defer os.Remove(tempFile.Name())

	// 2. Write the vul-report to the temp file
	reportJSON, err := json.Marshal(vr.Report)
	if err != nil {
		return "", err
	}
	if _, err := tempFile.Write(reportJSON); err != nil {
		return "", err
	}

	return tempFile.Name(), nil
}

func runCopa(ctx context.Context, reportFile string) error {
	registry := "dev-registry.default.svc.cluster.local:5000"
	targetImage := fmt.Sprintf("%s/nginx:1.25.3", registry)
	patchedTag := fmt.Sprintf("%s/nginx:1.25.3-patched", registry)

	copaReportFile, err := os.CreateTemp("", "copa-report-*.json")
	if err != nil {
		return err
	}
	defer os.Remove(copaReportFile.Name())

	opts := &types.Options{
		Image:      targetImage,
		Report:     reportFile,
		PatchedTag: patchedTag,

		Timeout: 15 * time.Minute,

		Scanner:     "trivy",
		IgnoreError: true,

		Format:   "openvex",
		Output:   copaReportFile.Name(),
		Progress: "plain",

		BkAddr:    "tcp://buildkitd:1234",
		Loader:    "docker",
		Platforms: []string{"linux/amd64"},
		Push:      true,

		PkgTypes: "os,library",
	}

	return patch.Patch(ctx, opts)
}

// Hande to write the vul-report as temp file and run the copa patch command
func (h *PatchContainersHandler) Handle(ctx context.Context, namespacedName client.ObjectKey) error {

	// 1. Write the vul-report to the temp file
	tempFile, err := h.writeVulReportToTempFile(ctx, namespacedName)
	if err != nil {
		return err
	}
	defer os.Remove(tempFile)

	// 2. Run the copa patch command\
	return runCopa(ctx, tempFile)
}
