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

# Manually list the expected Buildkit
buildkits = [
    {'name': 'dev', 'namespace': 'default'},
]

for bk in buildkits:
    local_resource(
        'buildkit-logs-%s' % bk['name'],
        serve_cmd='''
echo "Waiting for BuildKit pod %s..."
until kubectl get pods -n %s -l buildkit.seatgeek.io/name=%s 2>/dev/null | grep -q Running; do
    sleep 3
done
kubectl logs -n %s -l buildkit.seatgeek.io/name=%s -f --tail=100
''' % (bk['name'], bk['namespace'], bk['name'], bk['namespace'], bk['name']),
        resource_deps=['buildkit-operator'],
        labels=['buildkit'],
    )