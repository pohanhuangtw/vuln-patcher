# Step for Demo
1. Explain the workflow with the flow chart
   1. explain sbomscanner
   2. explain copa
2. Run `tilt up`
3. `docker push localhost:5000/nginx:1.25.3`, assume this is user registry
4. `curl http://localhost:5000/v2/nginx/tags/list` check the current result
5. See the Tilt UI
6. When the patch done
7. `curl http://localhost:5000/v2/nginx/tags/list` should created a new tag with `-patched` suffix
8. Compare with trivy scan
   1. original: `trivy image localhost:5000/nginx:1.25.3 --format json | jq '[.Results[].Vulnerabilities // [] | length] | add'` => 302 CVE
   2. patched: `trivy image localhost:5000/nginx:1.25.3-patched --format json | jq '[.Results[].Vulnerabilities // [] | length] | add'` => 147 CVE