package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	trivyFanalTypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	trivyTypes "github.com/aquasecurity/trivy/pkg/types"
	"k8s.io/apimachinery/pkg/runtime"

	sbomscannerv1alpha1 "github.com/kubewarden/sbomscanner/api/storage/v1alpha1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/config"
)

var scheme = runtime.NewScheme()

func main() {
	fmt.Println("=== vuln-patcher build ID: 2025-12-02-1 ===")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()

	if err := runCopaCLI(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("Image patched successfully!")
}

// ToTrivyReport converts VulnerabilityReport back to Trivy Report format.
func ToTrivyReport(sbomScannerReport sbomscannerv1alpha1.Report) (string, error) {
	trivyResults := make([]trivyTypes.Result, 0, len(sbomScannerReport.Results))

	for _, result := range sbomScannerReport.Results {
		trivyRes := toTrivyResult(result)
		trivyResults = append(trivyResults, trivyRes)
	}

	tempFile, err := os.Create("./vul-report/transformed-report.json")
	if err != nil {
		return "", err
	}
	defer tempFile.Close()

	family, name := inferOSFromVulnerabilities(sbomScannerReport.Results)

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

	reportJSON, err := json.Marshal(trivyReport)
	if err != nil {
		return "", err
	}
	if _, err := tempFile.Write(reportJSON); err != nil {
		return "", err
	}

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

// func toTrivyCVSS(cvssMap map[string]sbomscannerv1alpha1.CVSS) trivyDBTypes.VendorCVSS {
// 	if cvssMap == nil {
// 		return nil
// 	}

// 	vendorCVSS := make(trivyDBTypes.VendorCVSS, len(cvssMap))
// 	for sid, cvss := range cvssMap {
// 		v3Score, _ := strconv.ParseFloat(cvss.V3Score, 64)
// 		vendorCVSS[trivyDBTypes.SourceID(sid)] = trivyDBTypes.CVSS{
// 			V3Score:  v3Score,
// 			V3Vector: cvss.V3Vector,
// 		}
// 	}
// 	return vendorCVSS
// }

// func transformToTrivyReport(sbomScannerReportPath string) (string, error) {
// 	reportBytes, err := os.ReadFile(sbomScannerReportPath)
// 	if err != nil {
// 		return "", err
// 	}

// 	var sbomScannerReport sbomscannerv1alpha1.Report
// 	if err := json.Unmarshal(reportBytes, &sbomScannerReport); err != nil {
// 		return "", err
// 	}

// 	var trivyReport trivyTypes.Report
// 	if err := json.Unmarshal(reportBytes, &trivyReport); err != nil {
// 		return "", err
// 	}

// 	tempFile, err := os.CreateTemp(os.TempDir(), "trivy-report-*.json")
// 	if err != nil {
// 		return "", err
// 	}
// 	defer tempFile.Close()
// 	reportJSON, err := json.Marshal(trivyReport)
// 	if err != nil {
// 		return "", err
// 	}
// 	if _, err := tempFile.Write(reportJSON); err != nil {
// 		return "", err
// 	}
// 	return tempFile.Name(), nil
// }

func runCopaCLI(ctx context.Context) error {
	inK8sCluster := false
	var (
		bkAddr   string
		registry string
	)
	if inK8sCluster {
		bkAddr = "tcp://buildkitd:1234"
		registry = "dev-registry.default.svc.cluster.local:5000"
	} else {
		bkAddr = "docker-container://buildx_buildkit_neuvector0"
		registry = "docker.io"
	}
	targetImage := fmt.Sprintf("%s/nginx:1.25.3", registry)
	patchedTag := fmt.Sprintf("%s/nginx:1.25.3-patched", registry)

	sbomscannerv1alpha1.AddToScheme(scheme)
	k8sClient, err := client.New(config.GetConfigOrDie(), client.Options{Scheme: scheme})
	if err != nil {
		return err
	}

	var sbomScannerReport sbomscannerv1alpha1.VulnerabilityReport
	if err := k8sClient.Get(ctx, client.ObjectKey{Namespace: "default", Name: "68f3b4a9c5f4a00d904b2b5b12ae79080a2f2fad9080c978efa2de1da6577565"}, &sbomScannerReport); err != nil {
		return err
	}

	trivyReport, err := ToTrivyReport(sbomScannerReport.Report)
	if err != nil {
		return err
	}

	// defer os.Remove(trivyReport)

	args := []string{
		"patch",
		"--image", targetImage,
		"--report", trivyReport,
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

	cmd := exec.CommandContext(ctx, "copa", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// func runCopa(ctx context.Context) error {
// 	// Get BuildKit address
// 	inK8sCluster := true
// 	var (
// 		bkAddr   string
// 		registry string
// 	)
// 	if inK8sCluster {
// 		bkAddr = "tcp://buildkitd:1234"
// 		registry = "dev-registry.default.svc.cluster.local:5000"
// 	} else {
// 		bkAddr = "docker-container://buildx_buildkit_neuvector0"
// 		registry = "docker.io"
// 	}
// 	// Define paths
// 	targetImage := fmt.Sprintf("%s/nginx:1.25.3", registry)
// 	patchedTag := fmt.Sprintf("%s/nginx:1.25.3-patched", registry)

// 	opts := &types.Options{
// 		Image:      targetImage,
// 		Report:     "./vul-report/report.json",
// 		PatchedTag: patchedTag,

// 		Timeout: 15 * time.Minute,

// 		Scanner:     "trivy",
// 		IgnoreError: true,

// 		Format:   "openvex",
// 		Output:   "./vul-report/patched-report.json",
// 		Progress: "plain",

// 		BkAddr:    bkAddr,
// 		Loader:    "docker",
// 		Platforms: []string{"linux/amd64"},
// 		Push:      true,

// 		PkgTypes: "os,library",
// 	}

// 	log.Info("Starting patching process...")
// 	log.Infof("BuildKit address: %s", opts.BkAddr)
// 	deadline, ok := ctx.Deadline()
// 	if ok {
// 		log.Infof("Context deadline: %v", deadline)
// 	} else {
// 		log.Info("Context has no deadline")
// 	}

// 	// Check context status
// 	start := time.Now()
// 	log.Infof("[%v] Before patch.Patch", start)

// 	err := patch.Patch(ctx, opts)

// 	elapsed := time.Since(start)
// 	log.Infof("[%v] After patch.Patch (took %v), err: %v", time.Now(), elapsed, err)

// 	// Check if context was canceled
// 	select {
// 	case <-ctx.Done():
// 		log.Errorf("Context was canceled/deadline exceeded: %v", ctx.Err())
// 	default:
// 		log.Info("Context is still alive")
// 	}

// 	return err
// }
