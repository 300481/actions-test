# artifacthub2github example usage implementation with Argo CD

This folder contains an example implementation for the usage of the

serverless function [artifacthub2github](https://github.com/300481/artifacthub2github).

![](architecture.png)

## Files and Folders

### [.github/workflows/artifacthub-dispatch.yml](https://github.com/300481/actions-test/blob/main/.github/workflows/artifacthub-dispatch.yml)

This file is the workflow, which is triggered by the serverless function.

It will:

* save the payload

* update the chart-versions.yaml file

* generate the chart manifests

* generate a list with deprecated Kubernetes API versions for the chart

* generate a list of CVEs of the containers for the chart

* create a branch for the updated files

* create a pull request against the main branch

### [chart-versions.yaml](https://github.com/300481/actions-test/blob/main/artifacthub2github/chart-versions.yaml)

This file contains the current versions of the specific helm charts.

This file gets updated by the script triggered by the dispatch event.

### [process-artifacthub-dispatch.sh](https://github.com/300481/actions-test/blob/main/artifacthub2github/process-artifacthub-dispatch.sh)

The script which runs by the triggered workflow to run the steps.

### [shared-functions.sh](https://github.com/300481/actions-test/blob/main/artifacthub2github/shared-functions.sh)

The shared functions which are used by the processing script.
### [trivy.tpl](https://github.com/300481/actions-test/blob/main/artifacthub2github/templates/trivy.tpl)

This file is a template for templating a markdown file for the vulnerability reports of Trivy.

### [argocd-example-chart/chart-values](https://github.com/300481/actions-test/tree/main/artifacthub2github/argocd-example-chart/chart-values)

This folder contains the Helm Values for the charts.

You can have multiple values files to generate multiple manifests, for example for *`DEV`*, *`TEST`*, *`STAGING`* and *`PRODUCTION`*.

### [manifests](https://github.com/300481/actions-test/tree/main/artifacthub2github/processing-data/manifests)

This folder contains the generated chart manifest files for the charts and its corresponding values files.

### [deprecations](https://github.com/300481/actions-test/tree/main/artifacthub2github/processing-data/deprecations)

This folder contains the information about deprecated Kubernetes API versions which are used by the chart.

### [cves](https://github.com/300481/actions-test/tree/main/artifacthub2github/processing-data/cves)

This folder contains the information about found CVEs of the containers used in the chart.

### [last-payloads](https://github.com/300481/actions-test/tree/main/artifacthub2github/processing-data/last-payloads)

This folder contains the latest payloads and can be used to test the proper

function of the serverless function as of the worflow and scripts.

#### Example *curl* command for testing

```bash
curl -d @./processing-data/last-payloads/argo-cd-payload.json -H "X-ArtifactHub-Secret: [YOUR-ARTIFACTHUB-SECRET]" https://[YOUR-GCP-PROJECT].cloudfunctions.net/[YOUR-FUNCTION-NAME]
```

## Files you need to adopt this functionality

### The workflow file

[.github/workflows/artifacthub-dispatch.yml](https://github.com/300481/actions-test/blob/main/.github/workflows/artifacthub-dispatch.yml)

Adjust it to your needs.

### The script

* [process-artifacthub-dispatch.sh](https://github.com/300481/actions-test/blob/main/artifacthub2github/process-artifacthub-dispatch.sh)

* [shared-functions.sh](https://github.com/300481/actions-test/blob/main/artifacthub2github/shared-functions.sh)

### The chart values if needed

* [argocd-example-chart/chart-values](https://github.com/300481/actions-test/tree/main/artifacthub2github/argocd-example-chart/chart-values)

### The vulnerability report template if needed 

* [trivy.tpl](https://github.com/300481/actions-test/blob/main/artifacthub2github/processing-data/templates/trivy.tpl)
