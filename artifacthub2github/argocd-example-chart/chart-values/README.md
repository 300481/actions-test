# chart-values

In this folder are the environment specific values located for each chart.

By default here you'll find an empty `default.yaml` which is needed for processing

the artifacthub-dispatch event workflow, which generates the manifests, API deprecations and CVEs.

Put your environment specific values file in here, f.e. *dev.yaml*, *uat.yaml*, *prod.yaml*.

The artifacthub-dispatch event workflow will generate the manifests, API deprecations and CVEs

for each environment.
