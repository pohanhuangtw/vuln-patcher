package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/project-copacetic/copacetic/pkg/patch"
	"github.com/project-copacetic/copacetic/pkg/types"
	log "github.com/sirupsen/logrus"
)

func main() {
	fmt.Println("=== vuln-patcher build ID: 2025-12-02-1 ===")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()

	if err := runCopa(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("Image patched successfully!")
}

func runCopa(ctx context.Context) error {
	// Define paths
	registry := "dev-registry.default.svc.cluster.local:5000"
	targetImage := fmt.Sprintf("%s/nginx:1.25.3-alpine3.18", registry)
	patchedTag := fmt.Sprintf("%s/nginx:1.25.3-alpine3.18-patched", registry)
	tmpDir := "/tmp/copa-image-input"

	// Clean up previous run if exists
	os.RemoveAll(tmpDir)

	// Get BuildKit address
	bkAddr := os.Getenv("BUILDKIT_HOST")
	if bkAddr == "" {
		bkAddr = "tcp://buildkitd:1234"
	}

	opts := &types.Options{
		Image:       targetImage,
		Report:      "./vul-report/report.json",
		Scanner:     "trivy",
		PatchedTag:  patchedTag,
		Timeout:     15 * time.Minute,
		IgnoreError: true,
		Format:      "openvex",
		Output:      "./vul-report/patched-report.json",
		BkAddr:      bkAddr,
		PkgTypes:    "os",
		Loader:      "docker",
		// Platforms:   []string{"linux/amd64"},
	}

	log.Info("Starting patching process...")
	log.Infof("BuildKit address: %s", opts.BkAddr)
	deadline, ok := ctx.Deadline()
	if ok {
		log.Infof("Context deadline: %v", deadline)
	} else {
		log.Info("Context has no deadline")
	}

	// Check context status
	start := time.Now()
	log.Infof("[%v] Before patch.Patch", start)

	err := patch.Patch(ctx, opts)

	elapsed := time.Since(start)
	log.Infof("[%v] After patch.Patch (took %v), err: %v", time.Now(), elapsed, err)

	// Check if context was canceled
	select {
	case <-ctx.Done():
		log.Errorf("Context was canceled/deadline exceeded: %v", ctx.Err())
	default:
		log.Info("Context is still alive")
	}

	return err
}
