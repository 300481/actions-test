#!/usr/bin/env bash

. ./artifacthub2github/shared-functions.sh

REPO_NAME=$(repo_name "${PAYLOAD}")
CHART_NAME=$(chart_name "${PAYLOAD}")

manifestdir="${MANIFESTS_ROOT}/chart-manifests/${REPO_NAME}/${CHART_NAME}"
deprecationsdir="${DEPRECATIONS_ROOT}/chart-deprecations/${REPO_NAME}/${CHART_NAME}"
[[ -d ${manifestdir} ]] || mkdir -p ${manifestdir}
[[ -d ${deprecationsdir} ]] || mkdir -p ${deprecationsdir}
for manifestfile in ${manifestdir}/* ; do
    echo ${REPO_NAME} : ${CHART_NAME} : ${manifestfile}
    pluto detect ${manifestfile} --output markdown --ignore-deprecations --ignore-removals > ${deprecationsdir}/${manifestfile##*/}.api-deprecations.md
done
