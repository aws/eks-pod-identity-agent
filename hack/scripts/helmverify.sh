#!/bin/bash
helm="$1"

helm_template() {
    local template_path=$1
    local extra_args=$2

    echo "Generating template for eks-pod-identity-agent at ${template_path}"
    template=$(${helm} template ${extra_args} charts/eks-pod-identity-agent > ${template_path})
}

compare_templates() {
    local generated_template_path=$1
    local expected_template_path=$2

    diff_output=$(diff -u ${expected_template_path} ${generated_template_path})
    # Check if the diff output is empty
    if [ -z "$diff_output" ]; then
        echo "SUCCESS: No difference between ${expected_template_path} and ${generated_template_path}"
    else
        echo "ERROR: Difference found between ${expected_template_path} and ${generated_template_path}"
        echo "$diff_output"
        exit 1
    fi
}

tmp_dir=$(mktemp -d)
template_path=${tmp_dir}/template.yaml
expected_default_template_path=hack/testdata/expected_eks_pod_identity_agent_default_helm_template.yaml
expected_hybrid_template_path=hack/testdata/expected_eks_pod_identity_agent_hybrid_helm_template.yaml
expected_hybrid_bottlerocket_template_path=hack/testdata/expected_eks_pod_identity_agent_hybrid_bottlerocket_helm_template.yaml
expected_iso_template_path=hack/testdata/expected_eks_pod_identity_agent_iso_helm_template.yaml
expected_workload_identity_template_path=hack/testdata/expected_eks_pod_identity_agent_workload_identity_helm_template.yaml

echo "Validating default helm template for eks-pod-identity-agent"
helm_template ${template_path}
compare_templates ${template_path} ${expected_default_template_path}

echo "Validating hybrid helm template for eks-pod-identity-agent"
helm_template ${template_path} "--set daemonsets.hybrid.create=true
    --set nameOverride=eks-pod-identity-agent-custom-test-truncate-123213213121321121-this-part-should-be-truncated
    --set fullnameOverride=eks-pod-identity-agent-custom-test-truncate-123213213121321121-this-part-should-be-truncated"
compare_templates ${template_path} ${expected_hybrid_template_path}

echo "Validating Bottlerocket hybrid helm template for eks-pod-identity-agent"
helm_template ${template_path} "--set daemonsets.hybrid-bottlerocket.create=true
    --set nameOverride=eks-pod-identity-agent-custom-test-truncate-123213213121321121-this-part-should-be-truncated
    --set fullnameOverride=eks-pod-identity-agent-custom-test-truncate-123213213121321121-this-part-should-be-truncated"
compare_templates ${template_path} ${expected_hybrid_bottlerocket_template_path}

# An isolated region with workload identity asked for, which the region overrides: no flag,
# no CSIDriver object, no kubelet mounts, no host PID namespace.
echo "Validating isolated region helm template for eks-pod-identity-agent"
helm_template ${template_path} "--set env.AWS_REGION=us-iso-east-1 --set workloadIdentity.enabled=true"
compare_templates ${template_path} ${expected_iso_template_path}

# Workload identity on, across all three DaemonSets, which the chart tests check the wiring of.
echo "Validating workload identity helm template for eks-pod-identity-agent"
helm_template ${template_path} "--set workloadIdentity.enabled=true
    --set daemonsets.hybrid.create=true
    --set daemonsets.hybrid-bottlerocket.create=true"
compare_templates ${template_path} ${expected_workload_identity_template_path}

# The same, missing the csiDriver block, as helm upgrade --reuse-values leaves it when the
# release came from a chart that predates it. Must render, and identically.
echo "Validating workload identity helm template without csiDriver values for eks-pod-identity-agent"
helm_template ${template_path} "--set workloadIdentity.enabled=true
    --set daemonsets.hybrid.create=true
    --set daemonsets.hybrid-bottlerocket.create=true
    --set csiDriver=null"
compare_templates ${template_path} ${expected_workload_identity_template_path}

rm -rf ${tmp_dir}
