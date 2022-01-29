#!/usr/bin/env bash

: ${CONFIGFILE:=helm-charts.yaml}

PAYLOAD="${1}"

REPO_NAME=$(jq -r .data.package.repository.name <<< ${PAYLOAD})
REPO=$(sed 's/-/_/g' <<< ${REPO_NAME})
PUBLISHER=$(jq -r .data.package.repository.publisher <<< ${PAYLOAD})
CHART_NAME=$(jq -r .data.package.name <<< ${PAYLOAD})
CHART=$(sed 's/-/_/g' <<< ${CHART_NAME})
VERSION=$(jq -r .data.package.version <<< ${PAYLOAD})
REPO_URL=$(curl -s "https://artifacthub.io/api/v1/repositories/search?offset=0&limit=20&kind=0&user=${PUBLISHER}&org=${PUBLISHER}&name=${REPO_NAME}" | jq -r .[0].url)

echo "
Repository Name: ${REPO_NAME}
Repository URL:  ${REPO_URL}
Chart Name:      ${CHART_NAME}
Chart Version:   ${VERSION}
Publisher:       ${PUBLISHER}
"

# update repo url
yq eval '.repos.'${REPO}'.url = "'${REPO_URL}'"' -i ${CONFIGFILE}
# update repo name
yq eval '.repos.'${REPO}'.name = "'${REPO_NAME}'"' -i ${CONFIGFILE}
# update chart version
yq eval '.repos.'${REPO}'.charts.'${CHART}'.version = "'${VERSION}'"' -i ${CONFIGFILE}
# update chart name
yq eval '.repos.'${REPO}'.charts.'${CHART}'.name = "'${CHART_NAME}'"' -i ${CONFIGFILE}
