allow_k8s_contexts('default')

k8s_yaml("./hack/registry.yaml")

k8s_resource(
    "dev-registry",
    port_forwards=5000,
)

load("ext://helm_resource", "helm_resource")

helm_resource(
    "buildkit-operator",
    "oci://ghcr.io/seatgeek/charts/buildkit-operator",
    namespace="buildkit-system",
    flags=[
        "--create-namespace",
        "--skip-crds",
    ]
)

load("ext://namespace", "namespace_create")

# Use a dedicated dev namespace for this project
namespace_create("vulnpatcher")

# Build the controller image used by config/manager/manager.yaml
docker_build(
    'controller:latest',
    context='.',
    dockerfile='./Dockerfile',
)

k8s_yaml(kustomize('./config/default'))

k8s_resource(
    'vuln-patcher-controller-manager',
)

# Create log viewers for each namespace that might have BuildKit pods
# Each will automatically find the BuildKit pod in that namespace
def create_buildkit_log_viewer(namespace):
    """Create a log viewer that finds and follows BuildKit pod in a namespace"""
    local_resource(
        'buildkit-logs-%s' % namespace,
        '''#!/bin/bash
# Find BuildKit pod in namespace
pod=$(kubectl get pods -n %s -l app.kubernetes.io/name=buildkit -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)

if [ -z "$pod" ]; then
    echo "No BuildKit pod found in namespace %s. Waiting..."
    while [ -z "$pod" ]; do
        sleep 2
        pod=$(kubectl get pods -n %s -l app.kubernetes.io/name=buildkit -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
    done
fi

echo "Following logs for BuildKit pod: %s/$pod"
kubectl logs -n %s "$pod" -f --tail=100
''' % (namespace, namespace, namespace, namespace, namespace),
        resource_deps=['buildkit-operator'],
        labels=['buildkit'],
        ignore=['.'],
    )

# Create log viewers for common namespaces
for ns in ['default', 'vulnpatcher']:
    create_buildkit_log_viewer(ns)