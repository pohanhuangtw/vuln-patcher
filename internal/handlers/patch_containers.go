package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"strings"

	sbomscannerv1alpha1 "github.com/kubewarden/sbomscanner/api/storage/v1alpha1"

	trivyFanalTypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	trivyTypes "github.com/aquasecurity/trivy/pkg/types"

	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const PatchTagSuffix = "patch"

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

// ToTrivyReport converts VulnerabilityReport back to Trivy Report format.
func (h *PatchContainersHandler) transformSbomScannerToTrivy(vr sbomscannerv1alpha1.VulnerabilityReport) (string, error) {
	trivyResults := make([]trivyTypes.Result, 0, len(vr.Report.Results))

	for _, result := range vr.Report.Results {
		trivyRes := toTrivyResult(result)
		trivyResults = append(trivyResults, trivyRes)
	}

	family, name := inferOSFromVulnerabilities(vr.Report.Results)

	trivyReport := trivyTypes.Report{
		SchemaVersion: 2,
		Results:       trivyResults,
		Metadata: trivyTypes.Metadata{
			OS: &trivyFanalTypes.OS{
				Family: trivyFanalTypes.OSType(family),
				Name:   name,
			},
		},
	}

	// 4. Write the vul-report as temp file
	tempFile, err := os.CreateTemp(os.TempDir(), "vul-report-*.json")
	if err != nil {
		return "", err
	}
	defer tempFile.Close()

	reportJSON, err := json.Marshal(trivyReport)
	if err != nil {
		return "", fmt.Errorf("failed to marshal Trivy report: %w", err)
	}

	// 5. Write the Trivy-formatted report to the temp file
	if _, err := tempFile.Write(reportJSON); err != nil {
		return "", fmt.Errorf("failed to write report file: %w", err)
	}

	// Ensure data is flushed to disk
	if err := tempFile.Sync(); err != nil {
		return "", fmt.Errorf("failed to sync report file: %w", err)
	}

	h.logger.Info("wrote Trivy report to temp file", "path", tempFile.Name(), "size", len(reportJSON))
	return tempFile.Name(), nil
}

// inferOSFromVulnerabilities tries to infer OS family and name from package types in vulnerabilities
func inferOSFromVulnerabilities(results []sbomscannerv1alpha1.Result) (family, name string) {
	// Check PURLs to determine OS type
	for _, result := range results {
		for _, vuln := range result.Vulnerabilities {
			if vuln.PURL != "" {
				// Parse PURL to extract OS information
				// Example: pkg:deb/debian/curl@7.88.1-10+deb12u6?arch=amd64
				if strings.HasPrefix(vuln.PURL, "pkg:deb/") {
					// Debian-based OS
					parts := strings.Split(vuln.PURL, "/")
					if len(parts) >= 2 {
						osName := parts[1] // e.g., "debian"
						// Try to extract version from package name or PURL
						if strings.Contains(vuln.PURL, "deb12") {
							return "debian", "12"
						} else if strings.Contains(vuln.PURL, "deb11") {
							return "debian", "11"
						} else if strings.Contains(vuln.PURL, "deb10") {
							return "debian", "10"
						}
						return "debian", osName
					}
					return "debian", ""
				} else if strings.HasPrefix(vuln.PURL, "pkg:rpm/") {
					// RPM-based OS (RHEL, CentOS, Fedora, etc.)
					parts := strings.Split(vuln.PURL, "/")
					if len(parts) >= 2 {
						osName := parts[1]
						return "redhat", osName
					}
					return "redhat", ""
				} else if strings.HasPrefix(vuln.PURL, "pkg:apk/") {
					// Alpine Linux
					return "alpine", ""
				}
			}
		}
	}

	// Default fallback: if we can't determine, return empty
	return "", ""
}

func toTrivyResult(result sbomscannerv1alpha1.Result) trivyTypes.Result {
	trivyRes := trivyTypes.Result{
		Target: result.Target,
		Class:  trivyTypes.ResultClass(result.Class),
		Type:   trivyFanalTypes.TargetType(result.Type),
	}

	for _, vuln := range result.Vulnerabilities {
		if vuln.Suppressed {
			// Skip suppressed vulnerabilities or handle separately if needed
			continue
		}
		trivyRes.Vulnerabilities = append(trivyRes.Vulnerabilities, toTrivyVulnerability(vuln))
	}

	return trivyRes
}

func toTrivyVulnerability(vuln sbomscannerv1alpha1.Vulnerability) trivyTypes.DetectedVulnerability {
	return trivyTypes.DetectedVulnerability{
		VulnerabilityID:  vuln.CVE,
		PkgName:          vuln.PackageName,
		PkgPath:          strings.TrimPrefix(vuln.PackagePath, "/"),
		InstalledVersion: vuln.InstalledVersion,
		FixedVersion:     strings.Join(vuln.FixedVersions, ", "),
		Layer: trivyFanalTypes.Layer{
			DiffID: vuln.DiffID,
		},
	}
}

func (h *PatchContainersHandler) runCopaCLI(ctx context.Context, vulReport string, vr sbomscannerv1alpha1.VulnerabilityReport) error {
	// Harcoded
	bkAddr := "tcp://buildkitd.default.svc.cluster.local:1234"
	image := fmt.Sprintf("%s/%s:%s", vr.ImageMetadata.RegistryURI, vr.ImageMetadata.Repository, vr.ImageMetadata.Tag)
	patchedImage := fmt.Sprintf("%s/%s:%s-%s", vr.ImageMetadata.RegistryURI, vr.ImageMetadata.Repository, vr.ImageMetadata.Tag, PatchTagSuffix)

	args := []string{
		"patch",
		"--image", image,
		"--report", vulReport,
		"--tag", patchedImage,
		"--addr", bkAddr,
		"--loader", "docker",
		"--scanner", "trivy",
		"--format", "openvex",
		"--timeout", "15m",
		"--platform", vr.ImageMetadata.Platform,
		"--push",
		"--ignore-errors",
	}

	h.logger.Info("running copa patch",
		"image", image,
		"patchedTag", patchedImage,
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
		"patchedImage", patchedImage,
	)

	return nil
}

// Hande to write the vul-report as temp file and run the copa patch command
func (h *PatchContainersHandler) Handle(ctx context.Context, namespacedName client.ObjectKey) error {
	var vr sbomscannerv1alpha1.VulnerabilityReport
	if err := h.k8sClient.Get(ctx, namespacedName, &vr); err != nil {
		return err
	}

	vulReport, err := h.transformSbomScannerToTrivy(vr)
	if err != nil {
		return err
	}
	defer os.Remove(vulReport)

	return h.runCopaCLI(ctx, vulReport, vr)
}
