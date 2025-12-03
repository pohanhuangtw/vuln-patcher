package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"time"
)

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

func runCopaCLI(ctx context.Context) error {
	registry := "dev-registry.default.svc.cluster.local:5000"
	bkAddr := "tcp://buildkitd:1234"
	targetImage := fmt.Sprintf("%s/nginx:1.25.3", registry)
	patchedTag := fmt.Sprintf("%s/nginx:1.25.3-patched", registry)

	args := []string{
		"patch",
		"--image", targetImage,
		"--report", "./vul-report/report.json",
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
