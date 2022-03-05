# artifacthub2github example usage implementation with Argo CD

This folder contains an example implementation for the usage of the

serverless function [artifacthub2github](https://github.com/300481/artifacthub2github).

![](architecture.png)

## Files and Folders

### [.github/workflows/artifacthub-dispatch.yml](https://github.com/300481/actions-test/blob/main/.github/workflows/artifacthub-dispatch.yml)

This file is the workflow, which is triggered by the serverless function.

It will:

* update the helm-charts.yaml file

* generate the chart manifests

* generate a list with deprecated Kubernetes API versions for the chart

* generate a list of CVEs of the containers for the chart

* create a branch for the updated files

* create a pull request against the main branch

### [update-chart-versions.sh](https://github.com/300481/actions-test/blob/main/artifacthub2github/update-chart-versions.sh)

The script which runs by the triggered workflow to update the helm-charts.yaml.

### [generate-helm-manifests.sh](https://github.com/300481/actions-test/blob/main/artifacthub2github/generate-helm-manifests.sh)

The script which runs by the triggered workflow to generate the manifest-files.

### [generate-list-of-deprecated-api-versions.sh](https://github.com/300481/actions-test/blob/main/artifacthub2github/generate-list-of-deprecated-api-versions.sh)

The script which runs by the triggered workflow to generate the list of Kubernetes API deprecations.

### [generate-list-of-cves.sh](https://github.com/300481/actions-test/blob/main/artifacthub2github/generate-list-of-cves.sh)

The script which runs by the triggered workflow to generate the list of CVEs of the containers of a chart.

### [markdown.tpl](https://github.com/300481/actions-test/blob/main/artifacthub2github/markdown.tpl)

This file is a template for templating a markdown file for the vulnerability reports of Trivy.

### [argocd-example/chart-values](https://github.com/300481/actions-test/tree/main/artifacthub2github/argocd-example/chart-values)

This folder contains the Helm Values for the charts.

You can have multiple values files to generate multiple manifests, for example for *`DEV`*, *`TEST`*, *`STAGING`* and *`PRODUCTION`*.

### [chart-manifests](https://github.com/300481/actions-test/tree/main/artifacthub2github/chart-manifests)

This folder contains the generated chart manifest files for the charts and its corresponding values files.

### [chart-deprecations](https://github.com/300481/actions-test/tree/main/artifacthub2github/chart-deprecations)

This folder contains the information about deprecated Kubernetes API versions which are used by the chart.

### [chart-cves](https://github.com/300481/actions-test/tree/main/artifacthub2github/chart-cves)

This folder contains the information about found CVEs of the containers used in the chart.

### [example-payloads](https://github.com/300481/actions-test/tree/main/artifacthub2github/example-payloads)

This folder contains some example payloads to test the proper

function of the serverless function as of the worflow and scripts.

#### Example *curl* command for testing

```bash
curl -d @./example-payloads/argo-cd-payload.json -H "X-ArtifactHub-Secret: [YOUR-ARTIFACTHUB-SECRET]" https://[YOUR-GCP-PROJECT].cloudfunctions.net/[YOUR-FUNCTION-NAME]
```

## Files you need to adopt this functionality

### The workflow file

[.github/workflows/update-chart-versions.yml](https://github.com/300481/actions-test/blob/main/.github/workflows/update-chart-versions.yml)

Adjust it to your needs.

### The scripts

* [update-chart-versions.sh](https://github.com/300481/actions-test/blob/main/artifacthub2github/update-chart-versions.sh)

* [generate-helm-manifests.sh](https://github.com/300481/actions-test/blob/main/artifacthub2github/generate-helm-manifests.sh)
* [generate-list-of-deprecated-api-versions.sh](https://github.com/300481/actions-test/blob/main/artifacthub2github/generate-list-of-deprecated-api-versions.sh)

* [generate-list-of-cves.sh](https://github.com/300481/actions-test/blob/main/artifacthub2github/generate-list-of-cves.sh)

### The chart values if needed

* [argocd-example/chart-values](https://github.com/300481/actions-test/tree/main/artifacthub2github/argocd-example/chart-values)

### The vulnerability report template if needed 

* [markdown.tpl](https://github.com/300481/actions-test/blob/main/artifacthub2github/markdown.tpl)