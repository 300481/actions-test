#!/usr/bin/env bash

. ./artifacthub2github/shared-functions.sh

: ${CONFIGFILE:=helm-charts.yaml}

die(){
    RC=$1 ; shift
    echo $@
    exit $RC
}

[[ -z "${PAYLOAD}" ]] && die 2 "ERROR: empty payload"

REPO_NAME=$(repo_name "${PAYLOAD}")
REPO=$(yaml_compatible_name "${REPO_NAME}")
PUBLISHER=$(publisher "${PAYLOAD}")
CHART_NAME=$(chart_name "${PAYLOAD}")
CHART=$(yaml_compatible_name "${CHART_NAME}")
VERSION=$(version "${PAYLOAD}")
REPO_URL=$(repo_url "${PAYLOAD}")

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
