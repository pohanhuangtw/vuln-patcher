allow_k8s_contexts('default')

k8s_yaml("./hack/registry.yaml")

k8s_resource(
    "dev-registry",
    port_forwards=5000,
)

load("ext://namespace", "namespace_create")

# Manually deploy buildkit
k8s_yaml(['./hack/buildkit.yaml'])


# Use a dedicated dev namespace for this project
namespace_create("vulnpatcher")

# Build the controller image used by config/manager/manager.yaml
docker_build(
    'controller:latest',
    context='.',
    dockerfile='./Dockerfile',
)

# Deploy the CRDs, RBAC, and controller manager (PatchJobReconciler lives here)
k8s_yaml(kustomize('./config/default'))

# Optional: make the controller manager a first-class Tilt resource
k8s_resource(
    'vuln-patcher-controller-manager',
)
