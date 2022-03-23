#!/usr/bin/env bash

. ./artifacthub2github/shared-functions.sh

REPO_NAME=$(repo_name "${PAYLOAD}")
CHART_NAME=$(chart_name "${PAYLOAD}")
VERSION=$(version "${PAYLOAD}")
REPO_URL=$(repo_url "${PAYLOAD}")

echo "${REPO_NAME} | ${REPO_URL} | ${CHART_NAME} | ${VERSION}"

helm repo add ${REPO_NAME} ${REPO_URL}
helm repo update

valuesdir="${VALUES_ROOT}/chart-values/${REPO_NAME}/${CHART_NAME}"
manifestdir="${MANIFESTS_ROOT}/chart-manifests/${REPO_NAME}/${CHART_NAME}"
[[ -d ${manifestdir} ]] || mkdir -p ${manifestdir}
[[ -d ${valuesdir} ]] || $(mkdir -p ${valuesdir} ; touch ${valuesdir}/default.yaml)

for valuesfile in ${valuesdir}/* ; do
    manifestfile=${manifestdir}/$(basename ${valuesfile})
    helm template ${CHART_NAME} ${REPO_NAME}/${CHART_NAME} --version ${VERSION} --values ${valuesfile} > ${manifestfile}
done        
