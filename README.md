# vuln-patcher

## Problem
[sbomscanner](https://github.com/kubewarden/sbomscanner) is able to discover vulnerabilities, user usually found the result confusing, and not easy to patch it. [copa](https://github.com/project-copacetic/copacetic) a cli to patch the containers tool may help it, but it does not implement in the k8s env.

This project will create a controller to watch the sbomscanner's vulnerability cr and create a patch image and upload to the registry.

## Flow
1. Deploy `BuildKit` as a Kubernetes Deployment to ensure it is available for patching operations.
   - This Deployment will manage a shared `BuildKit` instance that can be used by multiple patching operations.
2. Watch and reconcile `sbomscanner` vulnerability CRs with a controller (on create/update).
3. Publish events for eligible CRs (e.g., vulnerable and not yet patched) to a NATS subject.
   - NATS acts as a message broker, enabling distributed and scalable event handling.
4. Create a NATS subscriber to process events:
   - The subscriber listens to the NATS subject and processes events sequentially or in parallel, depending on the configuration.
   - For each event:
     - Create a temporary Pod (e.g., `patxxx`) that connects to the `BuildKit` instance.
     - Run the `copa patch` CLI within the Pod using the image reference (and SBOM info if needed) to generate a patched image.
5. Push the patched image to the configured registry.
6. Create and maintain a new CRD (e.g., `PatchJob`) to track the patching status of each `VulnerabilityReport`. This CRD will:
   - Reference the `VulnerabilityReport` by name and namespace.
   - Store the generation of the `VulnerabilityReport` to determine if it is up to date.
   - Include fields for the patched image reference, patch status, and any relevant metadata.
7. On each reconciliation, compare the generation of the `VulnerabilityReport` with the stored generation in the `PatchJob` CRD to decide if re-patching is needed.
8. Update the `PatchJob` CRD with the latest patching information after processing.

### How to reconcile the vulnerability changes?
1. Create a new CRD (e.g., `PatchJob`) to track the patching status of each `VulnerabilityReport`.
2. Use the generation of the `VulnerabilityReport` to determine if it has been updated since the last patching operation.
3. Ensure that the `PatchJob` CRD is updated whenever a patch is applied or when the `VulnerabilityReport` changes.

## Limitation
- Only builds and pushes patched images; it does **not** automatically update Deployments/Pods to use the new image (at least in the first version).
- Depends on `sbomscanner` `VulnerabilityReport` CRs and their timer-based rescan behavior; we treat those CRs as read-only input and track patch state separately (annotations and/or our own CRD).
- Uses `copa` as an external CLI tool (via `os/exec`), there is no stable Go API integration yet.
- Scope is limited to images referenced by the vulnerability CRs; it does not scan or discover images by itself, and re-patching decisions are based on comparing current vs previously-seen vulnerability state.

## Implementation limitation
- no TLS between pod and buildkitin
- IgnoreError: true, // Ignore errors if packages are not available in repos
- Pull and operate with public registry
- Use root for patching
- User needs to manually install buildkit
- Use copa cli not lib, because the conflict issue with docker
- Does not support sbomscanner report format, will patch the upstream
   - manually transform, should patch the upstream to accept the general form
- currently we can not scale, I think 

## Status
The initial version (v1) of `vuln-patcher` is complete with the following features:
- Successfully integrates with `sbomscanner` to scan container images for vulnerabilities.
- Automatically triggers `PatchJob` to patch vulnerable images and push the patched images to the configured registry.
- Provides a functional workflow to manage vulnerabilities and generate patched images in a Kubernetes environment.

This version establishes the foundation for automated vulnerability patching in Kubernetes, focusing on core functionality and integration.

## Reference
- [kubespace](https://kubescape.io/) uses a CLI-based approach to patch images, not Kubernetes CRs.
   - It uses `BuildKit` as a service, so many `kubescape` commands can share the same `BuildKit` instance.
