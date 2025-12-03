package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/exec"

	sbomscannerv1alpha1 "github.com/kubewarden/sbomscanner/api/storage/v1alpha1"

	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type PatchContainersHandler struct {
	k8sClient             client.Client
	scheme                *runtime.Scheme
	trivyJavaDBRepository string
	logger                *slog.Logger
}

func NewPatchContainersHandler(k8sClient client.Client, scheme *runtime.Scheme, trivyJavaDBRepository string, logger *slog.Logger) *PatchContainersHandler {
	return &PatchContainersHandler{
		k8sClient:             k8sClient,
		scheme:                scheme,
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
	tempFile, err := os.CreateTemp(os.TempDir(), "vul-report-*.json")
	if err != nil {
		return "", err
	}
	defer tempFile.Close()

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

func (h *PatchContainersHandler) runCopaCLI(ctx context.Context, vulReport string) error {
	registry := "dev-registry.default.svc.cluster.local:5000"
	bkAddr := "tcp://buildkitd:1234"
	targetImage := fmt.Sprintf("%s/nginx:1.25.3", registry)
	patchedTag := fmt.Sprintf("%s/nginx:1.25.3-patched", registry)

	args := []string{
		"patch",
		"--image", targetImage,
		"--report", vulReport,
		"--tag", patchedTag,
		"--addr", bkAddr,
		"--loader", "docker",
		"--scanner", "trivy",
		"--format", "openvex",
		"--timeout", "15m",
		"--platform", "linux/amd64",
		"--push",
		"--ignore-errors",
	}

	h.logger.Info("running copa patch",
		"image", targetImage,
		"patchedTag", patchedTag,
		"report", vulReport,
		"buildkit", bkAddr,
	)

	cmd := exec.CommandContext(ctx, "/copa", args...)

	// Capture stdout and stderr to log them
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()

	// Log the output
	if stdout.Len() > 0 {
		h.logger.Info("copa stdout", "output", stdout.String())
	}
	if stderr.Len() > 0 {
		h.logger.Info("copa stderr", "output", stderr.String())
	}

	if err != nil {
		h.logger.Error("copa failed", "error", err, "exitCode", cmd.ProcessState.ExitCode())
		return fmt.Errorf("copa patch failed: %w", err)
	}

	h.logger.Info("copa patch completed successfully",
		"patchedImage", patchedTag,
	)

	return nil
}

// Hande to write the vul-report as temp file and run the copa patch command
func (h *PatchContainersHandler) Handle(ctx context.Context, namespacedName client.ObjectKey) error {
	vulReport, err := h.writeVulReportToTempFile(ctx, namespacedName)
	if err != nil {
		return err
	}
	defer os.Remove(vulReport)

	return h.runCopaCLI(ctx, vulReport)
}
