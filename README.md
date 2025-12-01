# vuln-patcher

## Problem
[sbomscanner](https://github.com/kubewarden/sbomscanner) is able to discover vulnerabilities, user usually found the result confusing, and not easy to patch it. copa https://github.com/project-copacetic/copacetic a cli to patch the containers tool may help it, but it does not implement in the k8s env.

This project will create a controller to watch the sbomscanner's vulnerability cr and create a patch image and upload to the registry.

## Flow
1. Watch and reconcile `sbomscanner` vulnerability CRs with a controller (on create/update).
2. For eligible CRs (e.g. vulnerable and not yet patched), run the `copa patch` CLI using the image reference (and SBOM info if needed) to generate a patched image.
3. Push the patched image to the configured registry.
4. Create and maintain a new CRD (e.g., `PatchStatus`) to track the patching status of each `VulnerabilityReport`. This CRD will:
   - Reference the `VulnerabilityReport` by name and namespace.
   - Store the generation of the `VulnerabilityReport` to determine if it is up to date.
   - Include fields for the patched image reference, patch status, and any relevant metadata.
5. On each reconciliation, compare the generation of the `VulnerabilityReport` with the stored generation in the `PatchStatus` CRD to decide if re-patching is needed.
6. Update the `PatchStatus` CRD with the latest patching information after processing.

### How to reconcile the vulnerability changes?
1. Create a new CRD (e.g., `PatchStatus`) to track the patching status of each `VulnerabilityReport`.
2. Use the generation of the `VulnerabilityReport` to determine if it has been updated since the last patching operation.
3. Ensure that the `PatchStatus` CRD is updated whenever a patch is applied or when the `VulnerabilityReport` changes.

## Limitation
- Only builds and pushes patched images; it does **not** automatically update Deployments/Pods to use the new image (at least in the first version).
- Depends on `sbomscanner` `VulnerabilityReport` CRs and their timer-based rescan behavior; we treat those CRs as read-only input and track patch state separately (annotations and/or our own CRD).
- Uses `copa` as an external CLI tool (via `os/exec`), there is no stable Go API integration yet.
- Scope is limited to images referenced by the vulnerability CRs; it does not scan or discover images by itself, and re-patching decisions are based on comparing current vs previously-seen vulnerability state.

## Reference
- [kubespace](https://kubescape.io/) uses a CLI-based approach to patch images, not Kubernetes CRs.