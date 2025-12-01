package main

import (
	"context"
	"time"

	"github.com/project-copacetic/copacetic/pkg/patch"
	"github.com/project-copacetic/copacetic/pkg/types"
)

func runCopa() error {
	opts := &types.Options{
		Image:       "myimage:tag",
		Report:      "../vul-report/report.json", // or "" if you want auto-OS detection
		PatchedTag:  "myimage:patched",
		Timeout:     5 * time.Minute,
		IgnoreError: false,
		Format:      "openvex",
		Output:      "../vul-report/patched-report.json",
	}

	return patch.Patch(context.Background(), opts)
}
